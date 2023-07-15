#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124827);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-7472",
    "CVE-2017-7487",
    "CVE-2017-7495",
    "CVE-2017-7533",
    "CVE-2017-7541",
    "CVE-2017-7542",
    "CVE-2017-7616",
    "CVE-2017-7645",
    "CVE-2017-7895",
    "CVE-2017-8797",
    "CVE-2017-8824",
    "CVE-2017-8890",
    "CVE-2017-8924",
    "CVE-2017-9074",
    "CVE-2017-9075",
    "CVE-2017-9076",
    "CVE-2017-9077",
    "CVE-2017-9242",
    "CVE-2017-9605",
    "CVE-2018-1000004",
    "CVE-2018-10021",
    "CVE-2018-10087"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1504)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A vulnerability was found in the Linux kernel where the
    keyctl_set_reqkey_keyring() function leaks the thread
    keyring. This allows an unprivileged local user to
    exhaust kernel memory and thus cause a
    DoS.(CVE-2017-7472)

  - A reference counter leak in Linux kernel in
    ipxitf_ioctl function was found which results in a use
    after free vulnerability that's triggerable from
    unprivileged userspace when IPX interface is
    configured.(CVE-2017-7487)

  - A vulnerability was found in the Linux kernel where
    filesystems mounted with data=ordered mode may allow an
    attacker to read stale data from recently allocated
    blocks in new files after a system 'reset' by abusing
    ext4 mechanics of delayed allocation.(CVE-2017-7495)

  - A race condition was found in the Linux kernel, present
    since v3.14-rc1 through v4.12. The race happens between
    threads of inotify_handle_event() and vfs_rename()
    while running the rename operation against the same
    file. As a result of the race the next slab data or the
    slab's free list pointer can be corrupted with
    attacker-controlled data, which may lead to the
    privilege escalation.(CVE-2017-7533)

  - Kernel memory corruption due to a buffer overflow was
    found in brcmf_cfg80211_mgmt_tx() function in Linux
    kernels from v3.9-rc1 to v4.13-rc1. The vulnerability
    can be triggered by sending a crafted NL80211_CMD_FRAME
    packet via netlink. This flaw is unlikely to be
    triggered remotely as certain userspace code is needed
    for this. An unprivileged local user could use this
    flaw to induce kernel memory corruption on the system,
    leading to a crash. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although it is unlikely.(CVE-2017-7541)

  - An integer overflow vulnerability in
    ip6_find_1stfragopt() function was found. A local
    attacker that has privileges (of CAP_NET_RAW) to open
    raw socket can cause an infinite loop inside the
    ip6_find_1stfragopt() function.(CVE-2017-7542)

  - Incorrect error handling in the set_mempolicy() and
    mbind() compat syscalls in 'mm/mempolicy.c' in the
    Linux kernel allows local users to obtain sensitive
    information from uninitialized stack data by triggering
    failure of a certain bitmap operation.(CVE-2017-7616)

  - The NFS2/3 RPC client could send long arguments to the
    NFS server. These encoded arguments are stored in an
    array of memory pages, and accessed using pointer
    variables. Arbitrarily long arguments could make these
    pointers point outside the array and cause an
    out-of-bounds memory access. A remote user or program
    could use this flaw to crash the kernel, resulting in
    denial of service.(CVE-2017-7645)

  - The NFSv2 and NFSv3 server implementations in the Linux
    kernel through 4.10.13 lacked certain checks for the
    end of a buffer. A remote attacker could trigger a
    pointer-arithmetic error or possibly cause other
    unspecified impacts using crafted requests related to
    fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c.(CVE-2017-7895)

  - It was found that the NFSv4 server in the Linux kernel
    did not properly validate layout type when processing
    NFSv4 pNFS LAYOUTGET and GETDEVICEINFO operands. A
    remote attacker could use this flaw to soft-lockup the
    system and thus cause denial of service.(CVE-2017-8797)

  - A use-after-free vulnerability was found in DCCP socket
    code affecting the Linux kernel since 2.6.16. This
    vulnerability could allow an attacker to their escalate
    privileges.(CVE-2017-8824)

  - The inet_csk_clone_lock function in
    net/ipv4/inet_connection_sock.c in the Linux kernel
    allows attackers to cause a denial of service (double
    free) or possibly have unspecified other impact by
    leveraging use of the accept system call. An
    unprivileged local user could use this flaw to induce
    kernel memory corruption on the system, leading to a
    crash. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely.(CVE-2017-8890)

  - The edge_bulk_in_callback function in
    drivers/usb/serial/io_ti.c in the Linux kernel allows
    local users to obtain sensitive information (in the
    dmesg ringbuffer and syslog) from uninitialized kernel
    memory by using a crafted USB device (posing as an
    io_ti USB serial device) to trigger an integer
    underflow.(CVE-2017-8924)

  - The IPv6 fragmentation implementation in the Linux
    kernel does not consider that the nexthdr field may be
    associated with an invalid option, which allows local
    users to cause a denial of service (out-of-bounds read
    and BUG) or possibly have unspecified other impact via
    crafted socket and send system calls. Due to the nature
    of the flaw, privilege escalation cannot be fully ruled
    out, although we believe it is unlikely.(CVE-2017-9074)

  - The sctp_v6_create_accept_sk function in
    net/sctp/ipv6.c in the Linux kernel mishandles
    inheritance, which allows local users to cause a denial
    of service or possibly have unspecified other impact
    via crafted system calls, a related issue to
    CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2017-9075)

  - The IPv6 DCCP implementation in the Linux kernel
    mishandles inheritance, which allows local users to
    cause a denial of service or possibly have unspecified
    other impact via crafted system calls, a related issue
    to CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2017-9076)

  - The tcp_v6_syn_recv_sock function in
    net/ipv6/tcp_ipv6.c in the Linux kernel mishandles
    inheritance, which allows local users to cause a denial
    of service or possibly have unspecified other impact
    via crafted system calls, a related issue to
    CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2017-9077)

  - The __ip6_append_data function in net/ipv6/ip6_output.c
    in the Linux kernel through 4.11.3 is too late in
    checking whether an overwrite of an skb data structure
    may occur, which allows local users to cause a denial
    of service (system crash) via crafted system
    calls.(CVE-2017-9242)

  - The vmw_gb_surface_define_ioctl function (accessible
    via DRM_IOCTL_VMW_GB_SURFACE_CREATE) in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel through 4.11.4 defines a backup_handle variable
    but does not give it an initial value. If one attempts
    to create a GB surface, with a previously allocated DMA
    buffer to be used as a backup buffer, the backup_handle
    variable does not get written to and is then later
    returned to user space, allowing local users to obtain
    sensitive information from uninitialized kernel memory
    via a crafted ioctl call.(CVE-2017-9605)

  - In the Linux kernel versions 4.12, 3.10, 2.6, and
    possibly earlier, a race condition vulnerability exists
    in the sound system allowing for a potential deadlock
    and memory corruption due to use-after-free condition
    and thus denial of service. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2018-1000004)

  - The code in the drivers/scsi/libsas/sas_scsi_host.c
    file in the Linux kernel allow a physically proximate
    attacker to cause a memory leak in the ATA command
    queue and, thus, denial of service by triggering
    certain failure conditions.(CVE-2018-10021)

  - The kernel_wait4 function in kernel/exit.c in the Linux
    kernel, when an unspecified architecture and compiler
    is used, might allow local users to cause a denial of
    service by triggering an attempted use of the -INT_MIN
    value.(CVE-2018-10087)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1504
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fc0febb");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
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

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
