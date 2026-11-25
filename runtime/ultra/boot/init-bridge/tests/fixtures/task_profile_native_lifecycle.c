/* Explicit host port. Production bodies are inserted without rewriting them. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define CONFIG_PREEMPT_RT 1
#define CONFIG_KRETPROBES 1
#define CONFIG_ARM64 1
#define CONFIG_HAVE_SYSCALL_TRACEPOINTS 1
#define MSU_INIT_BRIDGE_CFI_KCFI 1
#define MSU_TASK_PROFILE_NATIVE 1
#define MSU_TASK_PROFILE_DISABLE_ROOT_BIT 63
#define __NR_execve 221
#define __NR_execveat 281
#define __user
#define IS_ENABLED(x) (x)
#define MSU_TASK_PROFILE_MARKER_MAGIC 0x4d53544dU
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p, v) (*(p) = (v))
#define rcu_dereference_raw(p) (p)
#define __rcu
#define GFP_KERNEL 0
struct list_head { struct list_head *next, *prev; };
struct signal_struct { struct list_head thread_head; };
struct thread_info { unsigned long flags; };
struct task_struct {
    struct list_head tasks, thread_node;
    struct signal_struct *signal;
    unsigned long work;
    bool allowed;
    unsigned id;
    struct thread_info thread_info;
};
struct pt_regs { unsigned long regs[31]; int syscallno; };
static unsigned long regs_get_kernel_argument(struct pt_regs *regs, unsigned index) { return regs->regs[index]; }
struct kretprobe_instance { int dummy; };
typedef int (*kretprobe_handler_t)(struct kretprobe_instance *, struct pt_regs *);
struct kretprobe {
    kretprobe_handler_t handler, entry_handler;
    struct { unsigned long addr; } kp;
    int maxactive, nmissed;
};
typedef struct { unsigned long raw; } rwlock_t;
struct tracepoint_func { void *func, *data; };
struct tracepoint { struct tracepoint_func *funcs; };
struct runtime_field { u32 offset, bytes, owner_bytes; };
static struct { struct runtime_field values[1]; } msu_runtime_layout;
enum { MSU_DYN_task_struct_flags };
static struct { unsigned work_bit; } msu_task_profile_target;
#define MSU_DYN_FIELD(p, type, member) ((p)->member)
#define MSU_DYN_CONTAINER(p, type, member) ((struct type *)((char *)(p) - offsetof(struct type, member)))
#include "binding.inc"

static unsigned raw_depth, rcu_depth, sleeping_locks, scans, allocs, frees, probes, unregisters, syncs;
static int probe_error_at = -1, trace_error, close_error, private_error;
static bool context_atomic, retired, reclaimed, test_changing_mode;
static struct tracepoint enter_point, exit_point;
static struct tracepoint_func own[3], foreign[2];
static struct task_struct init_task, tasks[5];
#define current (&tasks[0])
static struct thread_info *msu_dynamic_task_thread_info(struct task_struct *task) { return &task->thread_info; }
static bool is_compat_task(void) { return false; }
static bool test_bit(unsigned bit, const unsigned long *word) { return !!(*word & (1UL << bit)); }
static int copy_from_user_nofault(void *out, const void *in, size_t bytes) { memcpy(out, in, bytes); return 0; }
static struct signal_struct signals[3];
static rwlock_t fixture_tasklist;
static const char *scenario;
static int type_checks, named_lookups;
static bool msu_task_profile_trace_registered, msu_task_profile_trace_active;
static struct tracepoint *msu_task_profile_tracepoint;
static int msu_task_profile_trace_bind_error = -ENODEV;
static bool msu_task_profile_target_ready(void) { return true; }
static bool in_task(void) { return !context_atomic; }
static bool in_atomic(void) { return context_atomic; }
static bool irqs_disabled(void) { return context_atomic; }
static unsigned long *msu_task_profile_work(struct task_struct *task) { return &task->work; }
static int msu_task_profile_marker_return(struct kretprobe_instance *, struct pt_regs *);
void msu_task_profile_sys_enter(void *, struct pt_regs *, long);
bool msu_task_profile_trace_ready(void);
#define DEFINE_RAW_SPINLOCK(name) int name
#define raw_spin_lock_irqsave(lock, flags) do { (void)(lock); (flags) = 0; assert(!raw_depth); raw_depth++; } while (0)
#define raw_spin_unlock_irqrestore(lock, flags) do { (void)(lock); (void)(flags); assert(raw_depth == 1); raw_depth--; } while (0)
static void read_lock(rwlock_t *lock) { assert(lock); sleeping_locks++; }
static void read_unlock(rwlock_t *lock) { assert(lock); }
static void rcu_read_lock(void) { assert(raw_depth); rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth == 1); rcu_depth--; reclaimed = retired; }
static void set_bit(unsigned bit, unsigned long *word) { assert(rcu_depth); *word |= 1UL << bit; }
static void clear_bit(unsigned bit, unsigned long *word) { assert(rcu_depth); *word &= ~(1UL << bit); }
#define mutex_lock(p) ((void)(p))
#define mutex_unlock(p) ((void)(p))
static int msu_task_profile_trace_lock;
static void *kzalloc(size_t bytes, int flags) { (void)flags; allocs++; return calloc(1, bytes); }
static void kfree(void *p) { assert(!raw_depth); if (p) { frees++; free(p); } }
static int register_kretprobe(struct kretprobe *p) { assert(p->handler); if ((int)probes == probe_error_at) return -EIO; probes++; return 0; }
static void unregister_kretprobe(struct kretprobe *p) { assert(p); assert(!raw_depth); probes--; unregisters++; }
static void tracepoint_synchronize_unregister(void) { assert(!msu_task_profile_trace_active); syncs++; }
static void link_tail(struct list_head *node, struct list_head *head) { node->next = head; node->prev = head->prev; head->prev->next = node; head->prev = node; }
static void unlink_rcu(struct list_head *node) { node->prev->next = node->next; node->next->prev = node->prev; }
static void replace_rcu(struct list_head *old, struct list_head *node) { node->next = old->next; node->prev = old->prev; old->prev->next = node; old->next->prev = node; }
static void foreign_callback(void) { }
bool msu_su_runtime_trace_mark_task(struct task_struct *task)
{
    assert(rcu_depth && raw_depth && !reclaimed);
    assert(++scans < 32);
    if (scans == 1) {
        if (!strcmp(scenario, "clone")) link_tail(&tasks[4].thread_node, &signals[0].thread_head);
        if (!strcmp(scenario, "leader-exit")) {
            unlink_rcu(&tasks[0].tasks); unlink_rcu(&tasks[0].thread_node); retired = true;
        }
        if (!strcmp(scenario, "de-thread")) {
            replace_rcu(&tasks[0].tasks, &tasks[1].tasks);
            unlink_rcu(&tasks[0].thread_node); retired = true;
        }
        if (test_changing_mode) own[1] = foreign[0];
    }
    return task->allowed;
}
static unsigned long fixture_lookup(const char *name)
{
    if (!strcmp(name, "__tracepoint_sys_enter")) return (unsigned long)&enter_point;
    if (!strcmp(name, "__tracepoint_sys_exit")) return (unsigned long)&exit_point;
    if (!strcmp(name, "init_task")) return (unsigned long)&init_task;
    if (!strcmp(name, "tasklist_lock")) return !strcmp(scenario, "bind-no-tasklist") ? 0 : (unsigned long)&fixture_tasklist;
    if (!strcmp(name, "syscall_regfunc")) return 0x1000;
    if (!strcmp(name, "syscall_unregfunc")) return 0x2000;
    if (!strcmp(name, "tracepoint_probe_register_prio")) return 0x3000;
    if (!strcmp(name, "tracepoint_probe_unregister")) return 0x4000;
    named_lookups++; return 0;
}
static int tracepoint_probe_register_prio(struct tracepoint *p, void *callback, void *data, int priority)
{
    assert(!raw_depth && !rcu_depth && priority == INT_MIN);
    if (trace_error) return trace_error;
    own[0] = (struct tracepoint_func){callback, data}; p->funcs = own;
    msu_task_profile_marker_return(NULL, NULL); return 0;
}
static int tracepoint_probe_unregister(struct tracepoint *p, void *callback, void *data)
{
    assert(!raw_depth && !rcu_depth && !msu_task_profile_trace_active);
    assert(own[0].func == callback && own[0].data == data);
    if (close_error) return close_error;
    if (own[1].func) {
        own[0] = own[1]; own[1] = (struct tracepoint_func){0};
    } else {
        p->funcs = NULL;
        for (unsigned i = 0; i < 5; i++) tasks[i].work = 0; /* Native last-subscriber unregfunc. */
    }
    msu_task_profile_marker_return(NULL, NULL); return 0;
}
static void check_trace_callback_type_sys_enter(void (*cb)(void *, struct pt_regs *, long)) { (void)cb; type_checks++; }
struct msu_runtime_btf_type { u32 kind, bytes, target_id; };
struct msu_runtime_btf_function { bool variadic; u32 argument_count, arguments[4]; };
struct msu_runtime_btf_field { u32 offset, bytes, owner_bytes, type_id; };
static int msu_runtime_btf_function(const char *name, struct msu_runtime_btf_function *out) { (void)name; (void)out; return -ENOENT; }
static int msu_init_bridge_resolve_cfi(const char *name, const void *cb, unsigned long *addr) { (void)name; (void)cb; (void)addr; return -ENOENT; }
static int msu_profile_pointer(u32 id, const char *name) { (void)id; (void)name; return 0; }
static int msu_profile_value(u32 id, u32 kind, u32 bytes, const char *name) { (void)id; (void)kind; (void)bytes; (void)name; return 0; }
static int msu_runtime_facts_field(const char *owner, const char *member, struct msu_runtime_btf_field *field)
{
    if (private_error) return private_error;
    field->type_id = 0;
    if (!strcmp(owner, "task_struct") && !strcmp(member, "tasks")) {
        field->owner_bytes = sizeof(struct task_struct); field->offset = offsetof(struct task_struct, tasks); field->bytes = sizeof(struct list_head);
    } else if (!strcmp(owner, "tracepoint") && !strcmp(member, "funcs")) {
        field->owner_bytes = sizeof(struct tracepoint); field->offset = offsetof(struct tracepoint, funcs); field->bytes = sizeof(void *);
    } else if (!strcmp(owner, "tracepoint_func")) {
        field->owner_bytes = sizeof(struct tracepoint_func); field->offset = !strcmp(member, "func") ? offsetof(struct tracepoint_func, func) : offsetof(struct tracepoint_func, data); field->bytes = sizeof(void *);
    } else return -ENOENT;
    return 0;
}
#include "producer.inc"
#include "consumer.inc"

static void setup(void)
{
    init_task.tasks.next = init_task.tasks.prev = &init_task.tasks;
    for (unsigned i = 0; i < 3; i++) signals[i].thread_head.next = signals[i].thread_head.prev = &signals[i].thread_head;
    for (unsigned i = 0; i < 5; i++) { tasks[i].id = i; tasks[i].allowed = i % 2 == 0; tasks[i].work = 1; tasks[i].signal = &signals[i < 2 || i == 4 ? 0 : 1]; }
    tasks[4].work = 0;
    link_tail(&tasks[0].tasks, &init_task.tasks); link_tail(&tasks[2].tasks, &init_task.tasks);
    for (unsigned i = 0; i < 4; i++) link_tail(&tasks[i].thread_node, &tasks[i].signal->thread_head);
    msu_runtime_layout.values[0].owner_bytes = sizeof(struct task_struct);
    msu_task_profile_target.work_bit = 0;
    msu_task_profile_marker_target = (struct msu_task_profile_marker_binding){
        .magic = MSU_TASK_PROFILE_MARKER_MAGIC, .schema = 1, .bytes = sizeof(struct msu_task_profile_marker_binding), .bound = 1,
        .task_bytes = sizeof(struct task_struct), .tasks_offset = offsetof(struct task_struct, tasks), .tasks_bytes = sizeof(struct list_head),
        .tracepoint_bytes = sizeof(struct tracepoint), .funcs_offset = offsetof(struct tracepoint, funcs), .funcs_bytes = sizeof(void *),
        .func_bytes = sizeof(struct tracepoint_func), .callback_offset = offsetof(struct tracepoint_func, func), .callback_bytes = sizeof(void *), .data_offset = offsetof(struct tracepoint_func, data), .data_bytes = sizeof(void *),
        .kretprobe_bytes = sizeof(struct kretprobe), .handler_offset = offsetof(struct kretprobe, handler), .handler_bytes = sizeof(void *),
        .entry_handler_offset = offsetof(struct kretprobe, entry_handler), .entry_handler_bytes = sizeof(void *),
        .kp_addr_offset = offsetof(struct kretprobe, kp.addr), .kp_addr_bytes = sizeof(void *),
        .maxactive_offset = offsetof(struct kretprobe, maxactive), .maxactive_bytes = sizeof(int), .nmissed_offset = offsetof(struct kretprobe, nmissed), .nmissed_bytes = sizeof(int), .rwlock_bytes = sizeof(rwlock_t), .rwlock_align = _Alignof(rwlock_t),
    };
    foreign[0] = (struct tracepoint_func){(void *)foreign_callback, NULL};
    assert(!msu_task_profile_trace_bind(fixture_lookup) || !strcmp(scenario, "bind-no-tasklist"));
}

int main(int argc, char **argv)
{
    assert(argc == 2); scenario = argv[1]; setup();
    if (!strcmp(scenario, "callback-no-peer")) { assert(!msu_profile_trace_callback(fixture_lookup)); assert(type_checks == 1 && !named_lookups); }
    else if (!strcmp(scenario, "rt-producer")) { struct msu_task_profile_marker_binding marker; assert(!msu_profile_marker(&marker)); assert(marker.tasks_bytes == sizeof(struct list_head)); }
    else if (!strcmp(scenario, "bind-no-tasklist")) assert(!msu_task_profile_trace_bind(fixture_lookup));
    else if (!strcmp(scenario, "private-fact-error")) { struct msu_task_profile_marker_binding marker; private_error = -EFAULT; assert(msu_profile_marker(&marker) == -EFAULT); }
    else if (!strcmp(scenario, "unused-lock-receipt")) { msu_task_profile_marker_target.rwlock_bytes ^= 1; assert(msu_task_profile_marker_ready()); }
    else if (!strcmp(scenario, "probe-register-error")) { probe_error_at = 2; assert(msu_task_profile_trace_open() == -EIO); assert(!probes && allocs == frees && !msu_task_profile_marker.opened); }
    else if (!strcmp(scenario, "trace-register-error")) { trace_error = -EPERM; assert(msu_task_profile_trace_open() == -EPERM); assert(!probes && allocs == frees); }
    else if (!strcmp(scenario, "close-order") || !strcmp(scenario, "close-error") || !strcmp(scenario, "probe-missed") || !strcmp(scenario, "rt-open") || !strcmp(scenario, "close-other-subscriber")) {
        assert(!msu_task_profile_trace_open()); assert(probes == 4 && msu_task_profile_trace_ready());
        if (!strcmp(scenario, "close-other-subscriber")) own[1] = foreign[0];
        if (!strcmp(scenario, "probe-missed")) { msu_task_profile_marker.probes[0]->nmissed = 1; assert(!msu_task_profile_trace_ready()); }
        if (!strcmp(scenario, "close-error")) { close_error = -EIO; assert(msu_task_profile_trace_close() == -EIO); assert(!msu_task_profile_trace_active && probes == 4 && !syncs); close_error = 0; }
        assert(!msu_task_profile_trace_close()); assert(!probes && allocs == frees && !msu_task_profile_marker.opened && syncs == 1 && unregisters == 4);
        if (!strcmp(scenario, "close-other-subscriber")) for (unsigned i = 0; i < 4; i++) assert(tasks[i].work & 1);
    } else {
        msu_task_profile_marker.opened = true;
        own[0] = (struct tracepoint_func){(void *)msu_task_profile_sys_enter, &msu_task_profile_trace_registered}; enter_point.funcs = own;
        if (!strcmp(scenario, "other-subscriber")) own[1] = foreign[0];
        if (!strcmp(scenario, "subscriber-remove")) { own[1] = foreign[0]; msu_task_profile_marker_return(NULL, NULL); own[1] = (struct tracepoint_func){0}; scans = 0; }
        if (!strcmp(scenario, "exit-subscriber")) exit_point.funcs = foreign;
        if (!strcmp(scenario, "mode-change")) test_changing_mode = true;
        if (!strcmp(scenario, "closed-no-scan")) msu_task_profile_marker.opened = false;
        if (!strcmp(scenario, "irrelevant-tracepoint")) {
            struct pt_regs regs = {0};
            assert(msu_task_profile_marker_entry(NULL, &regs) == 1);
        } else { context_atomic = true; msu_task_profile_marker_return(NULL, NULL); }
        assert(!raw_depth && !rcu_depth);
        if (!strcmp(scenario, "atomic-scan")) assert(!sleeping_locks);
        else if (!strcmp(scenario, "closed-no-scan") || !strcmp(scenario, "irrelevant-tracepoint")) assert(!scans);
        else if (!strcmp(scenario, "other-subscriber") || !strcmp(scenario, "exit-subscriber") || !strcmp(scenario, "mode-change")) { for (unsigned i = 0; i < 4; i++) assert(tasks[i].work & 1); }
        else { for (unsigned i = 0; i < 4; i++) assert((tasks[i].work & 1) == tasks[i].allowed); if (!strcmp(scenario, "clone")) assert(tasks[4].work & 1); if (retired) assert(reclaimed); }
    }
    puts("PASS"); return 0;
}
