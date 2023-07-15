#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124989);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-7263",
    "CVE-2013-7445",
    "CVE-2013-7446",
    "CVE-2014-4611",
    "CVE-2014-5471",
    "CVE-2014-9914",
    "CVE-2015-0571",
    "CVE-2015-8104",
    "CVE-2015-8950",
    "CVE-2016-2550",
    "CVE-2016-2847",
    "CVE-2016-4557",
    "CVE-2016-9178",
    "CVE-2017-9150",
    "CVE-2017-10661",
    "CVE-2017-14991",
    "CVE-2017-17558",
    "CVE-2017-1000370",
    "CVE-2018-10940",
    "CVE-2018-18021"
  );
  script_bugtraq_id(64686, 68218, 69396);

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1536)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The offset2lib patch as used in the Linux Kernel
    contains a vulnerability that allows a PIE binary to be
    execve()'ed with 1GB of arguments or environmental
    strings then the stack occupies the address 0x80000000
    and the PIE binary is mapped above 0x40000000
    nullifying the protection of the offset2lib patch. This
    affects Linux Kernel version 4.11.5 and earlier. This
    is a different issue than CVE-2017-1000371. This issue
    appears to be limited to i386 based
    systems.(CVE-2017-1000370i1/4%0

  - Integer overflow in the LZ4 algorithm implementation,
    as used in Yann Collet LZ4 before r118 and in the
    lz4_uncompress function in lib/lz4/lz4_decompress.c in
    the Linux kernel before 3.15.2, on 32-bit platforms
    might allow context-dependent attackers to cause a
    denial of service (memory corruption) or possibly have
    unspecified other impact via a crafted Literal Run that
    would be improperly handled by programs not complying
    with an API limitation, a different vulnerability than
    CVE-2014-4715.(CVE-2014-4611i1/4%0

  - The replace_map_fd_with_map_ptr function in
    kernel/bpf/verifier.c in the Linux kernel before 4.5.5
    does not properly maintain an fd data structure, which
    allows local users to gain privileges or cause a denial
    of service (use-after-free) via crafted BPF
    instructions that reference an incorrect file
    descriptor.(CVE-2016-4557i1/4%0

  - The usb_destroy_configuration() function, in
    'drivers/usb/core/config.c' in the USB core subsystem,
    in the Linux kernel through 4.14.5 does not consider
    the maximum number of configurations and interfaces
    before attempting to release resources. This allows
    local users to cause a denial of service, due to
    out-of-bounds write access, or possibly have
    unspecified other impact via a crafted USB device. Due
    to the nature of the flaw, privilege escalation cannot
    be fully ruled out, although we believe it is
    unlikely.(CVE-2017-17558i1/4%0

  - The cdrom_ioctl_media_changed function in
    drivers/cdrom/cdrom.c in the Linux kernel before 4.16.6
    allows local attackers to use a incorrect bounds check
    in the CDROM driver CDROM_MEDIA_CHANGED ioctl to read
    out kernel memory.(CVE-2018-10940i1/4%0

  - It was found that the parse_rock_ridge_inode_internal()
    function of the Linux kernel's ISOFS implementation did
    not correctly check relocated directories when
    processing Rock Ridge child link (CL) tags. An attacker
    with physical access to the system could use a
    specially crafted ISO image to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-5471i1/4%0

  - A flaw was found in the Linux kernel's implementation
    of Unix sockets. A server polling for client-socket
    data could put the peer socket on a wait list the peer
    socket could then close the connection, making the
    reference on the wait list no longer valid. This could
    lead to bypassing the permissions on a Unix socket and
    packets being injected into the stream, and could also
    panic the machine (denial of service).(CVE-2013-7446i1/4%0

  - The do_check function in kernel/bpf/verifier.c in the
    Linux kernel before 4.11.1 does not make the
    allow_ptr_leaks value available for restricting the
    output of the print_bpf_insn function, which allows
    local users to obtain sensitive address information via
    crafted bpf system calls.(CVE-2017-9150i1/4%0

  - The WLAN (aka Wi-Fi) driver for the Linux kernel 3.x
    and 4.x, as used in Qualcomm Innovation Center (QuIC)
    Android contributions for MSM devices and other
    products, does not verify authorization for private SET
    IOCTL calls, which allows attackers to gain privileges
    via a crafted application, related to
    wlan_hdd_hostapd.c and
    wlan_hdd_wext.c.(CVE-2015-0571i1/4%0

  - arch/arm64/kvm/guest.c in KVM in the Linux kernel
    before 4.18.12 on the arm64 platform mishandles the
    KVM_SET_ON_REG ioctl. This is exploitable by attackers
    who can create virtual machines. An attacker can
    arbitrarily redirect the hypervisor flow of control
    (with full register control). An attacker can also
    cause a denial of service (hypervisor panic) via an
    illegal exception return. This occurs because of
    insufficient restrictions on userspace access to the
    core register file, and because PSTATE.M validation
    does not prevent unintended execution
    modes.(CVE-2018-18021i1/4%0

  - A resource-exhaustion vulnerability was found in the
    kernel, where an unprivileged process could allocate
    and accumulate far more file descriptors than the
    process' limit. A local, unauthenticated user could
    exploit this flaw by sending file descriptors over a
    Unix socket and then closing them to keep the process'
    fd count low, thereby creating kernel-memory or
    file-descriptors exhaustion (denial of
    service).(CVE-2016-2550i1/4%0

  - The Linux kernel before 3.12.4 updates certain length
    values before ensuring that associated data structures
    have been initialized, which allows local users to
    obtain sensitive information from kernel stack memory
    via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system
    call, related to net/ipv4/ping.c, net/ipv4/raw.c,
    net/ipv4/udp.c, net/ipv6/raw.c, and
    net/ipv6/udp.c.(CVE-2013-7263i1/4%0

  - It is possible for a single process to cause an OOM
    condition by filling large pipes with data that are
    never read. A typical process filling 4096 pipes with 1
    MB of data will use 4 GB of memory and there can be
    multiple such processes, up to a
    per-user-limit.(CVE-2016-2847i1/4%0

  - The __get_user_asm_ex macro in
    arch/x86/include/asm/uaccess.h in the Linux kernel
    before 4.7.5 does not initialize a certain integer
    variable, which allows local users to obtain sensitive
    information from kernel stack memory by triggering
    failure of a get_user_ex call.(CVE-2016-9178i1/4%0

  - It was found that the x86 ISA (Instruction Set
    Architecture) is prone to a denial of service attack
    inside a virtualized environment in the form of an
    infinite loop in the microcode due to the way
    (sequential) delivering of benign exceptions such as
    #DB (debug exception) is handled. A privileged user
    inside a guest could use this flaw to create denial of
    service conditions on the host kernel.(CVE-2015-8104i1/4%0

  - The Direct Rendering Manager (DRM) subsystem in the
    Linux kernel through 4.x mishandles requests for
    Graphics Execution Manager (GEM) objects, which allows
    context-dependent attackers to cause a denial of
    service (memory consumption) via an application that
    processes graphics data, as demonstrated by JavaScript
    code that creates many CANVAS elements for rendering by
    Chrome or Firefox.(CVE-2013-7445i1/4%0

  - A flaw was found in the Linux kernel which does not
    initialize certain data structures used by DMA transfer
    on ARM64 based systems. This could allow local users to
    obtain sensitive information from kernel memory by
    triggering a dma_mmap call and reconstructing the
    data.(CVE-2015-8950i1/4%0

  - A race condition was found in the Linux kernel before
    version 4.11-rc1 in 'fs/timerfd.c' file which allows a
    local user to cause a kernel list corruption or
    use-after-free via simultaneous operations with a file
    descriptor which leverage improper 'might_cancel'
    queuing. An unprivileged local user could use this flaw
    to cause a denial of service of the system. Due to the
    nature of the flaw, privilege escalation cannot be
    fully ruled out, although we believe it is
    unlikely.(CVE-2017-10661i1/4%0

  - The sg_ioctl() function in 'drivers/scsi/sg.c' in the
    Linux kernel, from version 4.12-rc1 to 4.14-rc2, allows
    local users to obtain sensitive information from
    uninitialized kernel heap-memory locations via an
    SG_GET_REQUEST_TABLE ioctl call for
    '/dev/sg0'.(CVE-2017-14991i1/4%0

  - A race condition in the ip4_datagram_release_cb
    function in net/ipv4/datagram.c in the Linux kernel
    allows local users to gain privileges or cause a denial
    of service (use-after-free) by leveraging incorrect
    expectations about locking during multithreaded access
    to internal data structures for IPv4 UDP
    sockets.(CVE-2014-9914i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1536
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4db9b001");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0571");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-1000370");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BPF doubleput UAF Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.28-1.2.117",
        "kernel-devel-4.19.28-1.2.117",
        "kernel-headers-4.19.28-1.2.117",
        "kernel-tools-4.19.28-1.2.117",
        "kernel-tools-libs-4.19.28-1.2.117",
        "kernel-tools-libs-devel-4.19.28-1.2.117",
        "perf-4.19.28-1.2.117",
        "python-perf-4.19.28-1.2.117"];

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
