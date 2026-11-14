//! The restrictions the download helper puts on itself before it talks to a mirror.
//!
//! libalpm applies the same kind of restrictions in `alpm_sandbox_setup_child` (`sandbox.c`), with
//! Landlock in `sandbox_fs.c` and seccomp in `sandbox_syscalls.c`. Three things differ here, and
//! each one takes a right away rather than giving one:
//!
//! - Landlock grants no write access anywhere. libalpm must let its child write the download
//!   directory. This helper sends the body to its parent on a pipe instead, so it writes nothing.
//! - Landlock grants read access only to what a request reads: `/usr`, the resolver's
//!   configuration, and the certificate stores ([`READABLE`]). libalpm grants it to all of `/`.
//!   Whatever user the helper runs as, the secrets that user can read stay out of reach: a
//!   keyring, a home directory, an SSH key.
//! - Landlock also limits TCP `connect` to a list of ports and forbids `bind`, and scopes signals
//!   and abstract UNIX sockets to the helper, when the kernel supports it. It refuses a UNIX
//!   socket that a path names, except the resolver's (`RESOLVER_SOCKETS`).
//! - The system call filter also refuses `execve`, `execveat`, and any `clone` that makes a new
//!   process rather than a thread. A helper cannot start another program, and cannot leave a
//!   process behind that outlives it.
//! - The filter also refuses what Landlock does not cover: changing a file's mode, owner,
//!   extended attributes or times, and opening a raw or packet socket. It refuses `io_uring`,
//!   new namespaces, `userfaultfd`, and reading or writing another process's memory, which a
//!   transfer never needs.
//!
//! Each restriction fails closed. A kernel without Landlock is an error, as in libalpm, and
//! `DisableSandboxFilesystem` is the way to accept it.

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, LandlockStatus, NetPort,
    PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

/// The newest Landlock ABI this code asks for. An older kernel enforces what it supports.
///
/// ABI 9 adds the right to connect to a UNIX socket that a path names. Below it, the helper
/// reaches every such socket its user can open: Landlock's scope covers abstract sockets only,
/// and a system call filter cannot read the address `connect` is given.
const LANDLOCK_ABI: ABI = ABI::V9;

/// The one directory whose UNIX sockets the helper may connect to: `systemd-resolved`'s, which
/// `nss-resolve` asks for every name. It answers name lookups and nothing else.
///
/// Every other socket a path names is refused: a session bus starts programs for its user, and a
/// key agent signs for them.
const RESOLVER_SOCKETS: &str = "/run/systemd/resolve";

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
    // Added: file metadata. Landlock does not cover these, so without them a helper that runs
    // as root can set a setuid bit or a file capability on any binary, or give a file away.
    "chmod",
    "fchmod",
    "fchmodat",
    "fchmodat2",
    "chown",
    "chown32",
    "fchown",
    "fchown32",
    "fchownat",
    "lchown",
    "lchown32",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "setxattrat",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "removexattrat",
    "utime",
    "utimes",
    "utimensat",
    "utimensat_time64",
    "futimesat",
    // Added: kernel attack surface a transfer never needs. `io_uring` operations also bypass
    // this filter, which sees only the system call that submits them. A user namespace hands
    // the helper capabilities over kernel code that is otherwise out of its reach.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "unshare",
    "setns",
    "userfaultfd",
    // Added: another process's memory. Landlock refuses this across domains, but not when
    // `DisableSandboxFilesystem` turns it off.
    "process_vm_readv",
    "process_vm_writev",
];

/// Every path the helper may read, and what beneath it. A path that does not exist is skipped.
///
/// A request reads the dynamic linker's cache and the NSS modules under `/usr` when it resolves a
/// name, the resolver's configuration, and a certificate store. A rule on a symbolic link covers
/// its target: `/etc/resolv.conf` is often a link into `/run/systemd/resolve`, and `/lib` one
/// to `/usr/lib`. `SSL_CERT_FILE` and `SSL_CERT_DIR` are added when set, since they choose the
/// store the platform verifier reads.
///
/// Nothing here holds a secret. `/etc` as a whole is not listed, because it does: the keyring,
/// `shadow`, the host's SSH keys.
const READABLE: &[&str] = &[
    // Libraries, NSS modules, and the certificate bundles some distributions keep there.
    "/usr",
    "/lib",
    "/lib64",
    // Name resolution.
    "/etc/ld.so.cache",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/gai.conf",
    "/etc/services",
    "/etc/protocols",
    "/run/systemd/resolve",
    // Certificate stores: Arch and Debian, then Fedora, then openSUSE.
    "/etc/ssl/certs",
    "/etc/ssl/cert.pem",
    "/etc/ca-certificates",
    "/etc/pki/tls/certs",
    "/etc/pki/ca-trust/extracted",
    "/etc/ssl/ca-bundle.pem",
    "/var/lib/ca-certificates",
];

/// `CLONE_THREAD`, from `<linux/sched.h>`. The value is the same on every architecture.
const CLONE_THREAD: u64 = 0x0001_0000;

/// `AF_INET`, `AF_INET6` and `AF_PACKET`, from `<linux/socket.h>`.
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const AF_PACKET: u64 = 17;

/// `SOCK_RAW` and `SOCK_PACKET`, and the mask that leaves out `SOCK_NONBLOCK`/`SOCK_CLOEXEC`,
/// from `<linux/net.h>`.
const SOCK_RAW: u64 = 3;
const SOCK_PACKET: u64 = 10;
const SOCK_TYPE_MASK: u64 = 0xf;

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
pub(crate) fn apply(confinement: &Confinement<'_>) -> Result<Confined, String> {
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

    let landlock_abi = if confinement.filesystem { landlock(confinement.ports)? } else { None };
    if confinement.syscalls {
        seccomp()?;
    }
    Ok(Confined { landlock_abi })
}

/// What [`confine_self`](crate::confine_self) applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Confined {
    /// The Landlock ABI the kernel enforces, or `None` when Landlock was not asked for.
    ///
    /// A restriction newer than this ABI is not in force: TCP ports need 4, signals and abstract
    /// UNIX sockets need 6, and a UNIX socket that a path names needs 9.
    pub landlock_abi: Option<i32>,
}

/// Every path [`READABLE`] names, then those the certificate variables name.
fn readable_paths() -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = READABLE.iter().map(Into::into).collect();
    if let Some(file) = std::env::var_os("SSL_CERT_FILE") {
        paths.push(file.into());
    }
    // OpenSSL's spelling: several directories, separated by `:`.
    if let Some(directories) = std::env::var_os("SSL_CERT_DIR") {
        paths.extend(std::env::split_paths(&directories));
    }
    paths
}

/// Makes the file system non-executable, unwritable, and readable only at [`readable_paths`],
/// and limits TCP to `ports`. Returns the ABI the kernel enforces.
fn landlock(ports: &[u16]) -> Result<Option<i32>, String> {
    let fail = |error: landlock::RulesetError| format!("could not apply Landlock: {error}");

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
        .map_err(fail)?;
    for path in readable_paths() {
        // Opening follows a symbolic link, so the rule lands on its target. A path that cannot
        // be opened, usually because it does not exist here, is simply not granted.
        let Ok(fd) = PathFd::new(&path) else { continue };
        // A directory-only right on a file makes the kernel refuse the rule.
        let mut read: BitFlags<AccessFs> =
            if std::fs::metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                AccessFs::ReadFile | AccessFs::ReadDir
            } else {
                AccessFs::ReadFile.into()
            };
        if path == std::path::Path::new(RESOLVER_SOCKETS) {
            read |= AccessFs::ResolveUnix;
        }
        ruleset = ruleset.add_rule(PathBeneath::new(fd, read)).map_err(fail)?;
    }
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
    Ok(match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => Some(effective_abi as i32),
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => None,
    })
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

    // Landlock limits TCP only. A raw or packet socket reaches the network below it, when the
    // helper runs as root and keeps `CAP_NET_RAW`. A raw netlink socket stays allowed:
    // glibc's `getaddrinfo` opens one to list the local addresses.
    let socket = ScmpSyscall::from_name("socket").map_err(fail)?;
    let family = |value| ScmpArgCompare::new(0, ScmpCompareOp::Equal, value);
    let kind = |value| ScmpArgCompare::new(1, ScmpCompareOp::MaskedEqual(SOCK_TYPE_MASK), value);
    filter.add_rule_conditional(deny, socket, &[family(AF_PACKET)]).map_err(fail)?;
    for inet in [AF_INET, AF_INET6] {
        for raw in [SOCK_RAW, SOCK_PACKET] {
            filter.add_rule_conditional(deny, socket, &[family(inet), kind(raw)]).map_err(fail)?;
        }
    }

    filter.load().map_err(fail)
}
