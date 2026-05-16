# AppArmor profile for ebpf-guard
# This profile allows the minimum required permissions for ebpf-guard to function

#include <tunables/global>

profile ebpf-guard flags=(attach_disconnected, mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Basic capabilities required
  capability chown,
  capability dac_override,
  capability fowner,
  capability fsetid,
  capability kill,
  capability net_bind_service,
  capability net_raw,
  capability setgid,
  capability setuid,
  capability sys_admin,
  capability sys_resource,
  capability sys_ptrace,
  capability sys_nice,
  capability ipc_lock,
  capability sys_boot,
  capability lease,
  capability audit_write,
  capability setfcap,
  capability mknod,
  capability net_admin,
  capability sys_time,
  capability audit_control,
  capability block_suspend,
  capability dac_read_search,
  capability syslog,
  capability wake_alarm,
  capability audit_read,

  # Network access
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network raw,
  network packet,

  # eBPF operations
  capability bpf,
  capability perfmon,

  # File access
  / r,
  /** r,
  /proc/** r,
  /sys/** r,
  /sys/fs/bpf/** rw,
  /sys/kernel/debug/** r,
  /sys/kernel/debug/tracing/** rw,

  # Binary execution
  /usr/local/bin/ebpf-guard mr,
  /usr/bin/ebpf-guard mr,
  /bin/** mr,
  /usr/bin/** mr,
  /usr/local/bin/** mr,

  # Configuration
  /etc/ebpf-guard/** r,
  /etc/ssl/** r,
  /etc/resolv.conf r,

  # Runtime directories
  /run/** rwk,
  /var/run/** rwk,
  /tmp/** rwk,

  # Logs
  /var/log/ebpf-guard/** rw,

  # Deny dangerous operations
  deny /etc/shadow w,
  deny /etc/passwd w,
  deny /etc/group w,
  deny /root/** w,
  deny /home/*/.ssh/** w,

  # Signal handling
  signal (send) set=(kill, term, int, hup, usr1, usr2),
  signal (receive),

  # ptrace - required for process monitoring
  ptrace (read, trace),

  # Mount operations
  mount,
  umount,

  # Pivot root
  pivot_root,
}
