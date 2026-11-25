"""Read actual ARM64 Image export tables and their native pointer relocations."""
import re
import struct

MASK = (1 << 64) - 1


class ImagePointers:
    def __init__(self, image, table):
        self.image, self.relocations = image, {}
        known = getattr(table, "text_base", 0) or None
        header = len(image) >= 64 and image[56:60] == b"ARMd"
        text_offset = self.u64(8) if header else 0
        kimage = set(table.all_offsets("kimage_vaddr"))
        roots = []
        if len(kimage) == 1 and header:
            kimage = kimage.pop()
            for at in range(0, len(image) - 23, 8):
                record = self.record(at)
                if record and (record[0] - record[1]) & MASK == kimage + text_offset:
                    roots.append((at, (record[0] - kimage) & MASK))
        rooted = {base for _, base in roots}
        if len(rooted) > 1 or known is not None and rooted and known not in rooted:
            self.fail("BASE_CONFLICT")
        self.base = known if known is not None else next(iter(rooted), 0)
        if not (1 << 64) - (1 << 48) <= self.base <= MASK:
            self.fail("BASE_RANGE")
        memory_end = max([len(image)] + list(table.all_offsets("_end")))
        if header:
            declared = self.u64(16)
            if 0 < declared < (1 << 48):
                memory_end = max(memory_end, declared)
        for root, _ in roots:
            first = root
            while first >= 24 and self.record(first - 24) is not None:
                first -= 24
            at = first
            while True:
                record = self.record(at)
                if record is None:
                    break
                slot = (record[0] - self.base) & MASK
                if slot + 8 > memory_end:
                    self.fail("RELA_SLOT")
                if slot + 8 <= len(image):
                    old = self.relocations.get(slot)
                    if old is not None and old != record[1]:
                        self.fail("RELA_CONFLICT")
                    self.relocations[slot] = record[1]
                at += 24

    @staticmethod
    def fail(reason):
        raise ValueError("ULTRA_BRIDGE_KMI_IMAGE_POINTER:" + reason)

    def u64(self, at):
        if at < 0 or at > len(self.image) - 8:
            self.fail("BOUNDS")
        return struct.unpack_from("<Q", self.image, at)[0]

    def record(self, at):
        if at < 0 or at > len(self.image) - 24 or self.u64(at + 8) != 1027:
            return None
        slot = self.u64(at)
        if slot < (1 << 64) - (1 << 48) or slot % 8:
            return None
        return slot, self.u64(at + 16)

    def pointer(self, at, nullable=False):
        raw = self.u64(at)
        relocated = self.relocations.get(at)
        if raw and relocated is not None and raw != relocated:
            self.fail("RAW_RELA_CONFLICT")
        value = raw if relocated is None else relocated
        if not value and nullable:
            return None
        offset = (value - self.base) & MASK
        if offset >= len(self.image):
            self.fail("ADDRESS")
        return offset


def capture(image, table, config):
    def unique(name):
        values = set(table.all_offsets(name))
        if len(values) != 1:
            raise ValueError("ULTRA_BRIDGE_KMI_EXPORT_SYMBOL:" + name)
        return values.pop()

    def word(at, signed=False):
        if at < 0 or at > len(image) - 4:
            raise ValueError("ULTRA_BRIDGE_KMI_EXPORT_BOUNDS")
        return struct.unpack_from("<i" if signed else "<I", image, at)[0]

    def cstring(at):
        if at < 0 or at >= len(image):
            raise ValueError("ULTRA_BRIDGE_KMI_EXPORT_STRING_BOUNDS")
        end = image.find(b"\0", at, min(len(image), at + 512))
        if end < 0 or any(value < 32 or value > 126 for value in image[at:end]):
            raise ValueError("ULTRA_BRIDGE_KMI_EXPORT_STRING")
        return image[at:end].decode("ascii")

    relative = config.get("CONFIG_HAVE_ARCH_PREL32_RELOCATIONS") == "y"
    modversions = config.get("CONFIG_MODVERSIONS") == "y"
    stride = 12 if relative else 24
    pointers = None if relative else ImagePointers(image, table)

    def label(at, nullable=False):
        offset = at + word(at, signed=True) if relative else pointers.pointer(at, nullable)
        return "" if offset is None else cstring(offset)

    exports, names = [], set()
    for suffix, export_class in (("", "EXPORT_SYMBOL"), ("_gpl", "EXPORT_SYMBOL_GPL")):
        start, stop = unique("__start___ksymtab" + suffix), unique("__stop___ksymtab" + suffix)
        crcs = unique("__start___kcrctab" + suffix) if modversions else 0
        crc_stop = unique("__stop___kcrctab" + suffix) if modversions else 0
        if (not 0 <= start <= stop <= len(image) or start % (stride // 3) or (stop - start) % stride or
                modversions and (not 0 <= crcs <= crc_stop <= len(image) or
                (stop - start) // stride * 4 != crc_stop - crcs)):
            raise ValueError("ULTRA_BRIDGE_KMI_EXPORT_BOUNDS")
        for at in range(start, stop, stride):
            name, namespace = label(at + stride // 3), label(at + stride // 3 * 2, nullable=True)
            if not re.fullmatch(r"[A-Za-z0-9_.$]+", name) or name in names or unique("__ksymtab_" + name) != at:
                raise ValueError("ULTRA_BRIDGE_KMI_EXPORT_NAME:" + name)
            crc_at = crcs + (at - start) // stride * 4
            crc = (word(crc_at + word(crc_at, signed=True)) if config.get("CONFIG_MODULE_REL_CRCS") == "y"
                   else word(crc_at)) if modversions else 0
            exports.append((name, crc, export_class, namespace))
            names.add(name)
    if not exports:
        raise ValueError("ULTRA_BRIDGE_KMI_EXPORT_EMPTY")
    return exports
