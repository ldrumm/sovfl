#define _XOPEN_SOURCE 500// 200809l // sigaltstack

#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <ucontext.h>

#include <sys/time.h> // setrlimit
#include <sys/resource.h> // setrlimit
#include <sys/types.h> // pid_t / getpid
#include <unistd.h> // pid_t / getpid

#define DEFAULT_INCREMENT_GRANULARITY (1024)
#define DEFAULT_ALTSTACK_SIZE (SIGSTKSZ)
#define LOG_PREFIX "SP: "


#ifndef NDEBUG
#define DEBUG(...) fprintf(stderr, LOG_PREFIX __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#ifdef __x86_64__
#define STACK_GROWS_DOWN (1)
#else
#error unsupported architecture
#endif

#ifdef STACK_GROWS_DOWN
#define IS_UNDERFLOW(bottom, val) ((val) > (bottom))
#define IS_OVERFLOW(top, val) ((val) < (top))
#elif defined(STACK_GROWS_UP)
#define IS_UNDERFLOW(bottom, val) ((val) < (bottom))
#define IS_OVERFLOW(top, val) ((val) > (top))
#else
#error unsupported architecture
#endif

struct state {
    // Store the original ulimit at startup
    struct rlimit init_limit;
    struct sigaction oldactions;
    struct sigaction actions;
    stack_t oldsigaltstack;
    stack_t sigaltstack;
    uintptr_t sp_on_entry;
    // By how much do we increment the stack each invocation
    size_t incr;
} STATE;

// This is our alternate state, used by the instrumentation when the real user
// stack has run out
static unsigned char ALTSTACK[DEFAULT_ALTSTACK_SIZE]
    __attribute__((aligned(4096)));

static int is_stack_overflow(const siginfo_t *restrict info)
{
    // Some things are not stack overflow
    switch (info->si_code) {
    case SEGV_MAPERR:
    case SEGV_ACCERR:
    case SEGV_BNDERR:
    // TODO pkeys interact with signal handlers in weird ways, and I don't know
    // what I'm doing, so to be safe, don't pretend to know, and simply abort
    case SEGV_PKUERR: __builtin_unreachable();
    }
    if (IS_UNDERFLOW(STATE.sp_on_entry, (uintptr_t)info->si_addr)) {
        // The faulting address is below the start of the stack
        // e.g. on x86 `info->si_addr` is numerically greater than the stack
        // pointer at program start
        return 0;
    }
#if STACK_GROWS_DOWN
    if (IS_OVERFLOW((uintptr_t)info->si_addr, (uintptr_t)info->si_lower))
        return 1;
#else
    if (IS_OVERFLOW((uintptr_t)info->si_addr, (uintptr_t)info->si_upper))
        return 1;
#endif
    // Assume it's not an overflow and terminate
    return 0;
}

static void segv_handler(int sig, siginfo_t *info, void *ucontext)
{
// TODO be friendly here
#define RERAISE() abort() //(sig)
    // man: si_signo, si_errno, and si_code are defined for all signals
    // si_errno is generally unused on linux
    struct ucontext_t *ctx = ucontext;
    assert(ctx && "unable to detrmine stack pointer for user code");
    DEBUG("bounds of current sigaltstack are %#0lx and %#0lx\n",
            (size_t)ALTSTACK, sizeof ALTSTACK);
    DEBUG("received signal %#x\n", info->si_signo);
    if (!is_stack_overflow(info)) {
        DEBUG("SEGV does not appear to be the result of a stack overflow\n");
        RERAISE();
    }

    size_t stack_size = ctx->uc_stack.ss_size;
    struct rlimit old;
    // XXX This is not async-signal-safe
    if (getrlimit(RLIMIT_STACK, &old) == -1)
        goto err;

    DEBUG("current soft limit: %zu\n", old.rlim_cur);
    DEBUG("current hard limit: %zu\n", old.rlim_max);

    const size_t new_sz = old.rlim_cur + STATE.incr;
    if (new_sz >= STATE.init_limit.rlim_cur) {
        DEBUG("original ulimit exceeded. STACK OVERFLOW");
        RERAISE();
    }
    const struct rlimit new = {
        .rlim_cur = new_sz,
        .rlim_max = old.rlim_max
    };
    // XXX This is not async-signal-safe
    if (setrlimit(RLIMIT_STACK, &new) == -1)
        goto err;
    return;
err:
    perror("unable to increase stack size");
    abort();
    __builtin_unreachable();
}

/** Set the ulimit for stack size to something absurdly small. This allows us
 * to incrementally increase the size of the stack to the normal limit, tracing
 * as we go. This is expensive at first, but plateaus very quickly for programs
 * that aren't deeply recursive
 */
static void init_small_stack(struct state *restrict state)
{
    if (getrlimit(RLIMIT_STACK, &state->init_limit) == -1 ||
        setrlimit(
            RLIMIT_STACK,
            &(struct rlimit) {0, state->init_limit.rlim_max}
        ) == -1) {
            perror("unable to initialize tiny rlimit");
            abort();
    }
}

static void init_handlers(struct state *restrict state)
{
    // If the stack overflows, we won't be able to run our signal handlers so
    // we use an alternate signal stack, which we statically allocate and
    // register with the runtime
    if (sigaltstack(
        &(stack_t){
            .ss_sp = ALTSTACK,
            .ss_size = sizeof ALTSTACK,
            // The manpage for linux says this should be left as zero for
            // portability
            // .ss_flags = SS_AUTODISARM,
        },
        &state->oldsigaltstack
    ) == -1) {
        perror("unable to set alternate signal for SEGV handling on overflow");
        abort();
    }
    DEBUG("alternate stack configured\n");
    state->actions = (struct sigaction) {
        .sa_flags =
        // Call our sa_sigaction handler (3 argument form)
        SA_SIGINFO
        // We use an alternate stack, as initialized above. The value is
        // implicit, and the flag is all that's needed here
        | SA_ONSTACK,
        .sa_sigaction = segv_handler,
    };
    if (sigemptyset(&state->actions.sa_mask) == -1) {
        perror("unable to set signal mask");
        abort();
    }
    if (sigaction(SIGSEGV, &state->actions, &state->oldactions) == -1) {
        perror("unable to set SEGV handler for stack tracing");
        abort();
    }
}

static inline uintptr_t get_sp(void)
{
    uintptr_t sp;
#ifdef __x86_64__
    __asm__("movq %%rsp, %[sp]": [sp] "=r"(sp));
#elif __i386__
    __asm__("movl %%esp, %[sp]": [sp] "=r"(sp));
#else
#error unsupported architecture
#endif
    return sp;
}

static void print_report(void)
{
    struct rlimit l;
    if (getrlimit(RLIMIT_STACK, &l) == -1) {
        fputs("unable to determine final stack size\n", stderr);
        return;
    }
    fprintf(stderr, "final stack usage was %zu bytes\n", l.rlim_cur);
}

/** The main entry point for the library, called by the runtime. We set the
 * lowest priority allowed in order that we run before other constructor
 * functions that may have deep stacks */
static void __attribute__((constructor(101))) init_stack_size_tracing(void)
{
    // This is rough as it's the present sp, but it's probably good enough
    STATE.sp_on_entry = get_sp();
    STATE.incr = DEFAULT_INCREMENT_GRANULARITY;
    init_handlers(&STATE);
    init_small_stack(&STATE);
    atexit(print_report);
}
