#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124825);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2017-2584",
    "CVE-2017-2596",
    "CVE-2017-2636",
    "CVE-2017-2647",
    "CVE-2017-2671",
    "CVE-2017-5551",
    "CVE-2017-5669",
    "CVE-2017-5970",
    "CVE-2017-5986",
    "CVE-2017-6001",
    "CVE-2017-6074",
    "CVE-2017-6214",
    "CVE-2017-6348",
    "CVE-2017-6353",
    "CVE-2017-6951",
    "CVE-2017-7187",
    "CVE-2017-7261",
    "CVE-2017-7294",
    "CVE-2017-7308",
    "CVE-2017-18255",
    "CVE-2017-18270",
    "CVE-2017-18344"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1502)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The perf_cpu_time_max_percent_handler function in
    kernel/events/core.c in the Linux kernel before 4.11
    allows local users to cause a denial of service
    (integer overflow) or possibly have unspecified other
    impact via a large value, as demonstrated by an
    incorrect sample-rate calculation.(CVE-2017-18255)

  - In the Linux kernel before 4.13.5, a local user could
    create keyrings for other users via keyctl commands,
    setting unwanted defaults or causing a denial of
    service.(CVE-2017-18270)

  - The timer_create syscall implementation in
    kernel/time/posix-timers.c in the Linux kernel doesn't
    properly validate the sigevent-i1/4zsigev_notify field,
    which leads to out-of-bounds access in the show_timer
    function.(CVE-2017-18344)

  - arch/x86/kvm/emulate.c in the Linux kernel through
    4.9.3 allows local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (use-after-free) via a crafted application that
    leverages instruction emulation for fxrstor, fxsave,
    sgdt, and sidt.(CVE-2017-2584)

  - Linux kernel built with the KVM visualization support
    (CONFIG_KVM), with nested visualization(nVMX) feature
    enabled(nested=1), is vulnerable to host memory leakage
    issue. It could occur while emulating VMXON instruction
    in 'handle_vmon'. An L1 guest user could use this flaw
    to leak host memory potentially resulting in
    DoS.(CVE-2017-2596)

  - A race condition flaw was found in the N_HLDC Linux
    kernel driver when accessing n_hdlc.tbuf list that can
    lead to double free. A local, unprivileged user able to
    set the HDLC line discipline on the tty device could
    use this flaw to increase their privileges on the
    system.(CVE-2017-2636)

  - A flaw was found that can be triggered in
    keyring_search_iterator in keyring.c if type-i1/4zmatch
    is NULL. A local user could use this flaw to crash the
    system or, potentially, escalate their
    privileges.(CVE-2017-2647)

  - A race condition leading to a NULL pointer dereference
    was found in the Linux kernel's Link Layer Control
    implementation. A local attacker with access to ping
    sockets could use this flaw to crash the
    system.(CVE-2017-2671)

  - A vulnerability was found in the Linux kernel in
    'tmpfs' file system. When file permissions are modified
    via 'chmod' and the user is not in the owning group or
    capable of CAP_FSETID, the setgid bit is cleared in
    inode_change_ok(). Setting a POSIX ACL via 'setxattr'
    sets the file permissions as well as the new ACL, but
    doesn't clear the setgid bit in a similar way this
    allows to bypass the check in 'chmod'.(CVE-2017-5551)

  - The do_shmat function in ipc/shm.c in the Linux kernel,
    through 4.9.12, does not restrict the address
    calculated by a certain rounding operation. This allows
    privileged local users to map page zero and,
    consequently, bypass a protection mechanism that exists
    for the mmap system call. This is possible by making
    crafted shmget and shmat system calls in a privileged
    context.(CVE-2017-5669)

  - A vulnerability was found in the Linux kernel where
    having malicious IP options present would cause the
    ipv4_pktinfo_prepare() function to drop/free the dst.
    This could result in a system crash or possible
    privilege escalation.(CVE-2017-5970)

  - It was reported that with Linux kernel, earlier than
    version v4.10-rc8, an application may trigger a BUG_ON
    in sctp_wait_for_sndbuf if the socket tx buffer is
    full, a thread is waiting on it to queue more data, and
    meanwhile another thread peels off the association
    being used by the first thread.(CVE-2017-5986)

  - It was found that the original fix for CVE-2016-6786
    was incomplete. There exist a race between two
    concurrent sys_perf_event_open() calls when both try
    and move the same pre-existing software group into a
    hardware context.(CVE-2017-6001)

  - A use-after-free flaw was found in the way the Linux
    kernel's Datagram Congestion Control Protocol (DCCP)
    implementation freed SKB (socket buffer) resources for
    a DCCP_PKT_REQUEST packet when the IPV6_RECVPKTINFO
    option is set on the socket. A local, unprivileged user
    could use this flaw to alter the kernel memory,
    allowing them to escalate their privileges on the
    system.(CVE-2017-6074)

  - A flaw was found in the Linux kernel's handling of
    packets with the URG flag. Applications using the
    splice() and tcp_splice_read() functionality could
    allow a remote attacker to force the kernel to enter a
    condition in which it could loop
    indefinitely.(CVE-2017-6214)

  - The hashbin_delete function in net/irda/irqueue.c in
    the Linux kernel improperly manages lock dropping,
    which allows local users to cause a denial of service
    (deadlock) via crafted operations on IrDA
    devices.(CVE-2017-6348)

  - It was found that the code in net/sctp/socket.c in the
    Linux kernel through 4.10.1 does not properly restrict
    association peel-off operations during certain wait
    states, which allows local users to cause a denial of
    service (invalid unlock and double free) via a
    multithreaded application. This vulnerability was
    introduced by CVE-2017-5986 fix (commit
    2dcab5984841).(CVE-2017-6353)

  - The keyring_search_aux function in
    security/keys/keyring.c in the Linux kernel allows
    local users to cause a denial of service via a
    request_key system call for the 'dead' key
    type.(CVE-2017-6951)

  - The sg_ioctl function in drivers/scsi/sg.c in the Linux
    kernel allows local users to cause a denial of service
    (stack-based buffer overflow) or possibly have
    unspecified other impacts via a large command size in
    an SG_NEXT_CMD_LEN ioctl call, leading to out-of-bounds
    write access in the sg_write function.(CVE-2017-7187)

  - In was found that in the Linux kernel, in
    vmw_surface_define_ioctl() function in
    'drivers/gpu/drm/vmwgfx/vmwgfx_surface.c' file, a
    'num_sizes' parameter is assigned a user-controlled
    value which is not checked if it is zero. This is used
    in a call to kmalloc() and later leads to dereferencing
    ZERO_SIZE_PTR, which in turn leads to a GPF and
    possibly to a kernel panic.(CVE-2017-7261)

  - An out-of-bounds write vulnerability was found in the
    Linux kernel's vmw_surface_define_ioctl() function, in
    the 'drivers/gpu/drm/vmwgfx/vmwgfx_surface.c' file. Due
    to the nature of the flaw, privilege escalation cannot
    be fully ruled out, although we believe it is
    unlikely.(CVE-2017-7294)

  - It was found that the packet_set_ring() function of the
    Linux kernel's networking implementation did not
    properly validate certain block-size data. A local
    attacker with CAP_NET_RAW capability could use this
    flaw to trigger a buffer overflow, resulting in the
    crash of the system. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled
    out.(CVE-2017-7308)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1502
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e37118f9");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6001");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7308");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
