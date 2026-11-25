"""Validate the exact PID1 legacy direct-call binder input, without binding it."""
import io
import struct
import hashlib

DIRECT_NAMES = ("file_open_root", "getname_kernel", "groups_alloc", "putname")
DIRECT_MARKER = b"MAPLESU_DIRECT_V1\0" + b"\0".join(name.encode("ascii") for name in DIRECT_NAMES) + b"\0\0"
DIRECT_PREFIX = "msu_direct_target_"
DIRECT_V2_MAGIC = b"MAPLESU_DIRECT_V2\0"
DIRECT_TARGETS_V2 = ('__arm64_sys_execve', '__flush_icache_range', '__module_address', '__module_text_address', '__put_cred', '__vfs_getxattr', '__vmalloc_node_range', '__vmalloc_node_range_noprof', 'aarch64_insn_patch_text', 'abort_creds', 'alloc_uid', 'caches_clean_inval_pou', 'cancel_work', 'commit_creds', 'copy_from_kernel_nofault', 'copy_from_user_nofault', 'copy_to_kernel_nofault', 'copy_to_user_nofault', 'core_kernel_text', 'execmem_alloc', 'execmem_alloc_rw', 'execmem_free', 'file_open_root', 'filp_open', 'find_task_by_pid_ns', 'fortify_panic', 'free_nsproxy', 'fsnotify_add_mark', 'fsnotify_alloc_group', 'fsnotify_destroy_group', 'fsnotify_destroy_mark', 'fsnotify_get_group', 'fsnotify_get_mark', 'fsnotify_init_mark', 'fsnotify_put_group', 'fsnotify_put_mark', 'fsnotify_wait_marks_destroyed', 'get_mm_exe_file', 'get_task_cred', 'get_task_exe_file', 'getname_kernel', 'groups_alloc', 'groups_sort', 'is_subdir', 'iterate_dir', 'kernel_read', 'module_alloc', 'module_memfree', 'our_mnt', 'override_creds', 'path_get', 'path_mount', 'path_umount', 'prepare_creds', 'putname', 'revert_creds', 'schedule_on_each_cpu', 'seccomp_filter_release', 'security_cred_getsecid', 'security_secctx_to_secid', 'set_cred_ucounts', 'set_groups', 'set_memory_nx', 'set_memory_ro', 'set_memory_rw', 'set_memory_x', 'sha256', 'sync_icache_aliases', 'synchronize_rcu_tasks', 'task_work_add', 'vfree', 'vfs_getxattr', 'vfs_setxattr', 'vfs_write', 'vmalloc', 'vmalloc_noprof', 'vmalloc_user', 'vmalloc_user_noprof')


def marker_imports(raw):
    if raw == DIRECT_MARKER:
        return {name: name for name in DIRECT_NAMES}, None
    if not raw.startswith(DIRECT_V2_MAGIC):
        raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_MARKER")
    values = raw[len(DIRECT_V2_MAGIC):].split(b"\0")
    if values[-2:] != [b"", b""] or not values[:-2] or len(values[:-2]) % 2:
        raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_MARKER")
    try:
        values = [value.decode("ascii") for value in values[:-2]]
    except UnicodeDecodeError as error:
        raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_MARKER") from error
    pairs = list(zip(values[::2], values[1::2]))
    targets = [target for _, target in pairs]
    if (targets != sorted(set(targets)) or any(target not in DIRECT_TARGETS_V2 or
            alias != DIRECT_PREFIX + target for alias, target in pairs)):
        raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_MARKER")
    return dict(pairs), [{"alias": alias, "target": target} for alias, target in pairs]


def inspect(data, cfi_mode):
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(data))
    markers = [section for section in elf.iter_sections() if section.name == ".msu_direct_calls"]
    if not markers:
        for table in elf.iter_sections():
            if table["sh_type"] == "SHT_SYMTAB" and any(symbol.name.startswith(DIRECT_PREFIX)
                    for symbol in table.iter_symbols()):
                raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_UNDECLARED_ALIAS")
        return {"imports": [], "relocations": {}, "binding": "normal-kernel-module-loader"}
    if (cfi_mode != "legacy-lto-cfi" or elf.elfclass != 64 or not elf.little_endian or
            elf["e_type"] != "ET_REL" or elf["e_machine"] != "EM_AARCH64" or
            len(markers) != 1 or markers[0]["sh_type"] != "SHT_PROGBITS"):
        raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_MARKER")
    declared, pairs = marker_imports(markers[0].data())
    tables = [(index, section) for index, section in enumerate(elf.iter_sections())
              if section["sh_type"] == "SHT_SYMTAB"]
    if len(tables) != 1:
        raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_SYMBOL_TABLE")
    table_index, table = tables[0]
    if table["sh_entsize"] != 24 or table["sh_size"] % 24:
        raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_SYMBOL_TABLE")
    selected = {}
    for index, symbol in enumerate(table.iter_symbols()):
        if symbol.name.startswith(DIRECT_PREFIX) and symbol.name not in declared:
            raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_UNDECLARED_ALIAS:" + symbol.name)
        if symbol.name not in declared:
            continue
        if (symbol.name in selected or symbol["st_shndx"] != "SHN_UNDEF" or
                symbol["st_info"]["bind"] != "STB_GLOBAL" or
                symbol["st_info"]["type"] not in ("STT_NOTYPE", "STT_FUNC")):
            raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_SYMBOL:" + symbol.name)
        selected[symbol.name] = index
    if pairs is not None and set(selected) != set(declared):
        raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_DECLARED_ALIAS_MISSING")
    calls = {name: [] for name in selected}
    by_index = {index: name for name, index in selected.items()}
    for section in elf.iter_sections():
        if section["sh_type"] not in ("SHT_RELA", "SHT_REL") or section["sh_link"] != table_index:
            continue
        if (section["sh_type"] != "SHT_RELA" or section["sh_entsize"] != 24 or
                section["sh_size"] % 24 or not 0 <= section["sh_info"] < elf.num_sections()):
            raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_RELOCATION_TABLE")
        code = elf.get_section(section["sh_info"])
        for relocation in section.iter_relocations():
            name = by_index.get(relocation["r_info_sym"])
            if name is None:
                continue
            kind, at = relocation["r_info_type"], relocation["r_offset"]
            if (kind not in (282, 283) or relocation["r_addend"] != 0 or
                    code["sh_type"] != "SHT_PROGBITS" or not code["sh_flags"] & 4 or
                    at % 4 or at < 0 or at > code["sh_size"] - 4):
                raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_RELOCATION:" + name)
            instruction = struct.unpack_from("<I", code.data(), at)[0]
            if instruction & 0xfc000000 != (0x94000000 if kind == 283 else 0x14000000):
                raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_OPCODE:" + name)
            calls[name].append({"section": section.name, "offset": at, "type": kind})
    if not calls or any(not rows for rows in calls.values()):
        raise ValueError("ULTRA_BRIDGE_LEGACY_DIRECT_CALL_REQUIRED")
    result = {"imports": sorted(selected), "relocations": calls,
            "binding": "pid1-exact-marker-call26-jump26-shn-abs-before-init-module",
            "ordinaryImportsRetainLoaderChecks": True, "directSymbolCrcCheckedByLoader": False,
            "targetAbiQualified": False, "moduleLoaded": False}
    if pairs is not None:
        result.update(directImportsV2=pairs, directMarkerSha256=hashlib.sha256(markers[0].data()).hexdigest())
    return result
