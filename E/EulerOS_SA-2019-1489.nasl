#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124813);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-8374",
    "CVE-2015-8539",
    "CVE-2015-8543",
    "CVE-2015-8569",
    "CVE-2015-8575",
    "CVE-2015-8660",
    "CVE-2015-8746",
    "CVE-2015-8767",
    "CVE-2015-8785",
    "CVE-2015-8787",
    "CVE-2015-8812",
    "CVE-2015-8816",
    "CVE-2015-8944",
    "CVE-2015-8953",
    "CVE-2015-8956",
    "CVE-2015-8961",
    "CVE-2015-8962",
    "CVE-2015-8963",
    "CVE-2015-8964",
    "CVE-2015-8970",
    "CVE-2015-9004",
    "CVE-2016-0723"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1489)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - An information-leak vulnerability was found in the
    kernel when it truncated a file to a smaller size which
    consisted of an inline extent that was compressed. The
    data between the new file size and the old file size
    was not discarded and the number of bytes used by the
    inode were not correctly decremented, which gave the
    wrong report for callers of the stat(2) syscall. This
    wasted metadata space and allowed for the truncated
    data to be leaked, and data corruption or loss to
    occur. A caller of the clone ioctl could exploit this
    flaw by using only standard file-system operations
    without root access to read the truncated
    data.(CVE-2015-8374)

  - A flaw was found in the Linux kernel's key management
    system where it was possible for an attacker to
    escalate privileges or crash the machine. If a user key
    gets negatively instantiated, an error code is cached
    in the payload area. A negatively instantiated key may
    be then be positively instantiated by updating it with
    valid data. However, the -i1/4zupdate key type method
    must be aware that the error code may be
    there.(CVE-2015-8539)

  - A NULL pointer dereference flaw was found in the way
    the Linux kernel's network subsystem handled socket
    creation with an invalid protocol identifier. A local
    user could use this flaw to crash the
    system.(CVE-2015-8543)

  - An out-of-bounds flaw was found in the kernel, where
    the length of the sockaddr parameter was not checked in
    the pptp_bind() and pptp_connect() functions. As a
    result, more kernel memory was copied out than
    required, leaking information from the kernel stack
    (including kernel addresses). A local system user could
    exploit this flaw to bypass kernel ASLR or leak other
    information.(CVE-2015-8569)

  - An out-of-bounds flaw was found in the kernel, where
    the sco_sock_bind() function (bluetooth/sco) did not
    check the length of its sockaddr parameter. As a
    result, more kernel memory was copied out than
    required, leaking information from the kernel stack
    (including kernel addresses). A local user could
    exploit this flaw to bypass kernel ASLR or leak other
    information.(CVE-2015-8575)

  - The ovl_setattr function in fs/overlayfs/inode.c in the
    Linux kernel through 4.3.3 attempts to merge distinct
    setattr operations, which allows local users to bypass
    intended access restrictions and modify the attributes
    of arbitrary overlay files via a crafted
    application.(CVE-2015-8660)

  - A NULL pointer dereference flaw was found in the Linux
    kernel: the NFSv4.2 migration code improperly
    initialized the kernel structure. A local,
    authenticated user could use this flaw to cause a panic
    of the NFS client (denial of service).(CVE-2015-8746)

  - A race condition flaw was found in the way the Linux
    kernel's SCTP implementation handled sctp_accept()
    during the processing of heartbeat timeout events. A
    remote attacker could use this flaw to prevent further
    connections to be accepted by the SCTP server running
    on the system, resulting in a denial of
    service.(CVE-2015-8767)

  - An infinite-loop flaw was found in the kernel. When a
    local user calls the sys_writev syscall with a
    specially crafted sequence of iov structs, the
    fuse_fill_write_pages kernel function might never
    terminate, instead continuing in a tight loop. This
    process cannot be terminated and requires a
    reboot.(CVE-2015-8785)

  - A NULL-pointer dereference vulnerability was found in
    the Linux kernel's TCP stack, in
    net/netfilter/nf_nat_redirect.c in the
    nf_nat_redirect_ipv4() function. A remote,
    unauthenticated user could exploit this flaw to create
    a system crash (denial of service).(CVE-2015-8787)

  - A use-after-free flaw was found in the CXGB3 kernel
    driver when the network was considered to be congested.
    The kernel incorrectly misinterpreted the congestion as
    an error condition and incorrectly freed or cleaned up
    the socket buffer (skb). When the device then sent the
    skb's queued data, these structures were referenced. A
    local attacker could use this flaw to panic the system
    (denial of service) or, with a local account, escalate
    their privileges.(CVE-2015-8812)

  - The hub_activate function in drivers/usb/core/hub.c in
    the Linux kernel before 4.3.5 does not properly
    maintain a hub-interface data structure, which allows
    physically proximate attackers to cause a denial of
    service (invalid memory access and system crash) or
    possibly have unspecified other impact by unplugging a
    USB hub device.(CVE-2015-8816)

  - The ioresources_init function in kernel/resource.c in
    the Linux kernel through 4.7, as used in Android before
    2016-08-05 on Nexus 6 and 7 (2013) devices, uses weak
    permissions for /proc/iomem, which allows local users
    to obtain sensitive information by reading this file,
    aka Android internal bug 28814213 and Qualcomm internal
    bug CR786116. NOTE: the permissions may be intentional
    in most non-Android contexts.(CVE-2015-8944)

  - 'A flaw was found in the Linux kernel's implementation
    of overlayfs. An attacker can leak file resources in
    the system by opening a large file with write
    permissions on a overlay filesystem that is
    insufficient to deal with the size of the write.

  - When unmounting the underlying device, the system is
    unable to free an inode and this will consume
    resources. Repeating this for all available inodes and
    memory will create a denial of service
    situation.(CVE-2015-8953)'

  - The rfcomm_sock_bind function in
    net/bluetooth/rfcomm/sock.c in the Linux kernel before
    4.2 allows local users to obtain sensitive information
    or cause a denial of service (NULL pointer dereference)
    via vectors involving a bind system call on a Bluetooth
    RFCOMM socket.(CVE-2015-8956)

  - A flaw was found in the ext4 subsystem. This
    vulnerability is a use after free vulnerability was
    found in __ext4_journal_stop(). Attackers could abuse
    this to allow any code which attempts to deal with the
    journal failure to be mishandled or not fail at all.
    This could lead to data corruption or
    crashes.(CVE-2015-8961)

  - A flaw was found in the Linux kernel SCSI subsystem,
    which allowed a local user to gain privileges or cause
    a denial of service (memory corruption and system
    crash) by issuing an SG_IO ioctl call while a device
    was being detached.(CVE-2015-8962)

  - Race condition in kernel/events/core.c in the Linux
    kernel before 4.4 allows local users to gain privileges
    or cause a denial of service via use-after-free
    vulnerability by leveraging incorrect handling of an
    swevent data structure during a CPU unplug
    operation.(CVE-2015-8963)

  - The tty_set_termios_ldisc() function in
    'drivers/tty/tty_ldisc.c' in the Linux kernel before
    4.5 allows local users to obtain sensitive information
    from kernel memory by reading a tty data
    structure.(CVE-2015-8964)

  - The lrw_crypt() function in 'crypto/lrw.c' in the Linux
    kernel before 4.5 allows local users to cause a system
    crash and a denial of service by the NULL pointer
    dereference via accept(2) system call for AF_ALG socket
    without calling setkey() first to set a cipher
    key.(CVE-2015-8970)

  - It was found that kernel/events/core.c in the Linux
    kernel mishandles counter grouping, which allows local
    users to gain privileges via a crafted application,
    related to the perf_pmu_register and perf_event_open
    functions.(CVE-2015-9004)

  - A use-after-free flaw was discovered in the Linux
    kernel's tty subsystem, which allows for the disclosure
    of uncontrolled memory location and possible kernel
    panic. The information leak is caused by a race
    condition when attempting to set and read the tty line
    discipline. A local attacker could use the TIOCSETD
    (via tty_set_ldisc ) to switch to a new line discipline
    a concurrent call to a TIOCGETD ioctl performing a read
    on a given tty could then access previously allocated
    memory. Up to 4 bytes could be leaked when querying the
    line discipline or the kernel could panic with a
    NULL-pointer dereference.(CVE-2016-0723)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1489
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fe461bc");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Overlayfs Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
