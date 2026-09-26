//! The restrictions the download helper puts on itself before it talks to a mirror.
//!
//! libalpm applies the same kind of restrictions in `alpm_sandbox_setup_child` (`sandbox.c`), with
//! Landlock in `sandbox_fs.c` and seccomp in `sandbox_syscalls.c`. Three things differ here, and
//! each one takes a right away rather than giving one:
//!
//! - Landlock grants no write access anywhere. libalpm must let its child write the download
//!   directory. This helper sends the body to its parent on a pipe instead, so it writes nothing.
//! - Landlock also limits TCP `connect` to a list of ports and forbids `bind`, and scopes signals
//!   and abstract UNIX sockets to the helper, when the kernel supports it.
//! - The system call filter also refuses `execve`, `execveat`, and any `clone` that makes a new
//!   process rather than a thread. A helper cannot start another program, and cannot leave a
//!   process behind that outlives it.
//!
//! Each restriction fails closed. A kernel without Landlock is an error, as in libalpm, and
//! `DisableSandboxFilesystem` is the way to accept it.

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

/// The newest Landlock ABI this code asks for. An older kernel enforces what it supports.
const LANDLOCK_ABI: ABI = ABI::V6;

/// The system calls libalpm refuses (`sandbox_syscalls.c`), in the same groups.
///
/// A name the running architecture does not have is skipped, as libalpm skips it.
const DENIED: &[&str] = &[
    // kernel modules
    "delete_module",
    "finit_module",
    "init_module",
    // mount
    "chroot",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "mount",
    "mount_setattr",
    "move_mount",
    "open_tree",
    "pivot_root",
    "umount",
    "umount2",
    // keyring
    "add_key",
    "keyctl",
    "request_key",
    // CPU emulation
    "modify_ldt",
    "subpage_prot",
    "switch_endian",
    "vm86",
    "vm86old",
    // debug
    "kcmp",
    "lookup_dcookie",
    "perf_event_open",
    "pidfd_getfd",
    "ptrace",
    "rtas",
    "sys_debug_setcontext",
    // set clock
    "adjtimex",
    "clock_adjtime",
    "clock_adjtime64",
    "clock_settime",
    "clock_settime64",
    "settimeofday",
    // raw IO
    "ioperm",
    "iopl",
    "pciconfig_iobase",
    "pciconfig_read",
    "pciconfig_write",
    // kexec
    "kexec_file_load",
    "kexec_load",
    // reboot
    "reboot",
    // privileged
    "acct",
    "bpf",
    "capset",
    "fanotify_init",
    "fanotify_mark",
    "nfsservctl",
    "open_by_handle_at",
    "personality",
    // obsolete
    "_sysctl",
    "afs_syscall",
    "bdflush",
    "break",
    "create_module",
    "ftime",
    "get_kernel_syms",
    "getpmsg",
    "gtty",
    "idle",
    "lock",
    "mpx",
    "prof",
    "profil",
    "putpmsg",
    "query_module",
    "security",
    "sgetmask",
    "ssetmask",
    "stime",
    "stty",
    "sysfs",
    "tuxcall",
    "ulimit",
    "uselib",
    "ustat",
    "vserver",
    // swap
    "swapon",
    "swapoff",
    // Added to libalpm's list: no new program, and no new process.
    "execve",
    "execveat",
    "fork",
    "vfork",
];

/// `CLONE_THREAD`, from `<linux/sched.h>`. The value is the same on every architecture.
const CLONE_THREAD: u64 = 0x0001_0000;

/// What the helper is allowed to keep.
#[derive(Clone, Debug)]
pub(crate) struct Confinement<'a> {
    /// Apply Landlock.
    pub(crate) filesystem: bool,
    /// Apply the system call filter.
    pub(crate) syscalls: bool,
    /// The TCP ports `connect` may reach.
    pub(crate) ports: &'a [u16],
}

/// Applies every restriction to the calling process.
///
/// The helper calls this once, first, before it reads anything a mirror sent.
///
/// # Errors
///
/// A message naming the restriction that could not be applied.
pub(crate) fn apply(confinement: &Confinement<'_>) -> Result<(), String> {
    // A core dump would write the process's memory, TLS secrets included, to disk.
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit { current: Some(0), maximum: Some(0) },
    )
    .map_err(|error| format!("could not disable core dumps: {error}"))?;

    // Set on its own, even when both restrictions below are disabled, as libalpm does. It is
    // also what lets an unprivileged process load a seccomp filter.
    rustix::thread::set_no_new_privs(true)
        .map_err(|error| format!("could not set no_new_privs: {error}"))?;

    if confinement.filesystem {
        landlock(confinement.ports)?;
    }
    if confinement.syscalls {
        seccomp()?;
    }
    Ok(())
}

/// Makes the file system read-only and non-executable, and limits TCP to `ports`.
fn landlock(ports: &[u16]) -> Result<(), String> {
    let fail = |error: landlock::RulesetError| format!("could not apply Landlock: {error}");
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let root =
        PathFd::new("/").map_err(|error| format!("could not open / for Landlock: {error}"))?;

    let mut ruleset = Ruleset::default()
        // Best effort for everything newer than ABI 1: an older kernel enforces less. The status
        // check below refuses a kernel that enforces nothing.
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(LANDLOCK_ABI))
        .map_err(fail)?
        .handle_access(AccessNet::from_all(LANDLOCK_ABI))
        .map_err(fail)?
        .scope(Scope::AbstractUnixSocket | Scope::Signal)
        .map_err(fail)?
        .create()
        .map_err(fail)?
        .add_rule(PathBeneath::new(root, read))
        .map_err(fail)?;
    let connect: BitFlags<AccessNet> = AccessNet::ConnectTcp.into();
    for &port in ports {
        ruleset = ruleset.add_rule(NetPort::new(port, connect)).map_err(fail)?;
    }
    let status = ruleset.restrict_self().map_err(fail)?;

    if status.ruleset == RulesetStatus::NotEnforced {
        return Err("could not apply Landlock: the kernel does not support it \
                    (set DisableSandboxFilesystem to download without it)"
            .to_owned());
    }
    Ok(())
}

/// Loads the system call filter.
fn seccomp() -> Result<(), String> {
    let fail = |error: libseccomp::error::SeccompError| {
        format!("could not apply the system call filter: {error}")
    };
    let deny = ScmpAction::Errno(rustix::io::Errno::PERM.raw_os_error());

    let mut filter = ScmpFilterContext::new(ScmpAction::Allow).map_err(fail)?;
    for name in DENIED {
        // An unknown name is a system call this architecture does not have.
        if let Ok(syscall) = ScmpSyscall::from_name(name) {
            filter.add_rule(deny, syscall).map_err(fail)?;
        }
    }

    // A thread is allowed, a new process is not. glibc starts a thread with `clone3` first, whose
    // flags sit in memory where a filter cannot read them. So `clone3` answers `ENOSYS`, glibc
    // falls back to `clone`, and `clone`'s flags are argument 0 on every architecture Arch Linux
    // builds for.
    let clone = ScmpSyscall::from_name("clone").map_err(fail)?;
    let not_a_thread = ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(CLONE_THREAD), 0);
    filter.add_rule_conditional(deny, clone, &[not_a_thread]).map_err(fail)?;
    if let Ok(clone3) = ScmpSyscall::from_name("clone3") {
        let enosys = ScmpAction::Errno(rustix::io::Errno::NOSYS.raw_os_error());
        filter.add_rule(enosys, clone3).map_err(fail)?;
    }

    filter.load().map_err(fail)
}
