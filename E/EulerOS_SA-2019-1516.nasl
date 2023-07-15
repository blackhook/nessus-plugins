#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124837);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2013-7265",
    "CVE-2014-0069",
    "CVE-2014-4027",
    "CVE-2015-5283",
    "CVE-2016-2065",
    "CVE-2016-2549",
    "CVE-2016-3672",
    "CVE-2016-4486",
    "CVE-2016-5344",
    "CVE-2016-6213",
    "CVE-2016-6480",
    "CVE-2016-9555",
    "CVE-2016-9685",
    "CVE-2017-1000363",
    "CVE-2017-13715",
    "CVE-2017-15102",
    "CVE-2017-17862",
    "CVE-2017-7308",
    "CVE-2017-8925",
    "CVE-2018-10074"
  );
  script_bugtraq_id(
    64677,
    65588,
    67985,
    68159
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1516)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The hi3660_stub_clk_probe function in
    drivers/clk/hisilicon/clk-hi3660-stub.c in the Linux
    kernel before 4.16 allows local users to cause a denial
    of service (NULL pointer dereference) by triggering a
    failure of resource retrieval.(CVE-2018-10074i1/4%0

  - An information leak flaw was found in the RAM Disks
    Memory Copy (rd_mcp) backend driver of the iSCSI Target
    subsystem of the Linux kernel. A privileged user could
    use this flaw to leak the contents of kernel memory to
    an iSCSI initiator remote client.(CVE-2014-4027i1/4%0

  - It was found that in the Linux kernel version 4.2-rc1
    to 4.3-rc1, a use of uninitialized 'n_proto',
    'ip_proto', and 'thoff' variables in
    __skb_flow_dissect() function can lead to a remote
    denial-of-service via malformed MPLS
    packet.(CVE-2017-13715i1/4%0

  - It was found that the packet_set_ring() function of the
    Linux kernel's networking implementation did not
    properly validate certain block-size data. A local
    attacker with CAP_NET_RAW capability could use this
    flaw to trigger a buffer overflow, resulting in the
    crash of the system. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled
    out.(CVE-2017-7308i1/4%0

  - A weakness was found in the Linux ASLR implementation.
    Any user able to running 32-bit applications in a x86
    machine can disable ASLR by setting the RLIMIT_STACK
    resource to unlimited.(CVE-2016-3672i1/4%0

  - sound/soc/msm/qdsp6v2/msm-audio-effects-q6-v2.c in the
    MSM QDSP6 audio driver for the Linux kernel 3.x, as
    used in Qualcomm Innovation Center (QuIC) Android
    contributions for MSM devices and other products,
    allows attackers to cause a denial of service
    (out-of-bounds write and memory corruption) or possibly
    have unspecified other impact via a crafted application
    that makes an ioctl call triggering incorrect use of a
    parameters pointer.(CVE-2016-2065i1/4%0

  - A race condition flaw was found in the ioctl_send_fib()
    function in the Linux kernel's aacraid implementation.
    A local attacker could use this flaw to cause a denial
    of service (out-of-bounds access or system crash) by
    changing a certain size value.(CVE-2016-6480i1/4%0

  - The omninet_open function in
    drivers/usb/serial/omninet.c in the Linux kernel before
    4.10.4 allows local users to cause a denial of service
    (tty exhaustion) by leveraging reference count
    mishandling.(CVE-2017-8925i1/4%0

  - The tower_probe function in
    drivers/usb/misc/legousbtower.c in the Linux kernel
    before 4.8.1 allows local users (who are physically
    proximate for inserting a crafted USB device) to gain
    privileges by leveraging a write-what-where condition
    that occurs after a race condition and a NULL pointer
    dereference.(CVE-2017-15102i1/4%0

  - The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel before 4.5.5
    does not initialize a certain data structure, which
    allows local users to obtain sensitive information from
    kernel stack memory by reading a Netlink
    message.(CVE-2016-4486i1/4%0

  - A vulnerability was found in the Linux kernel's
    lp_setup() function where it doesn't apply any bounds
    checking when passing 'lp=none'. This can result into
    overflow of the parport_nr array. An attacker with
    control over kernel command line can overwrite kernel
    code and data with fixed (0xff)
    values.(CVE-2017-1000363i1/4%0

  - sound/core/hrtimer.c in the Linux kernel before 4.4.1
    does not prevent recursive callback access, which
    allows local users to cause a denial of service
    (deadlock) via a crafted ioctl call.(CVE-2016-2549i1/4%0

  - The pn_recvmsg function in net/phonet/datagram.c in the
    Linux kernel before 3.12.4 updates a certain length
    value before ensuring that an associated data structure
    has been initialized, which allows local users to
    obtain sensitive information from kernel stack memory
    via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system
    call.(CVE-2013-7265i1/4%0

  - A NULL pointer dereference flaw was found in the SCTP
    implementation. A local user could use this flaw to
    cause a denial of service on the system by triggering a
    kernel panic when creating multiple sockets in parallel
    while the system did not have the SCTP module
    loaded.(CVE-2015-5283i1/4%0

  - It was found that in Linux kernel the mount table
    expands by a power-of-two with each bind mount command.
    If a system is configured to allow non-privileged user
    to do bind mounts, or allows to do so in a container or
    unprivileged mount namespace, then non-privileged user
    is able to cause a local DoS by overflowing the mount
    table, which causes a deadlock for the whole
    system.(CVE-2016-6213i1/4%0

  - The cifs_iovec_write function in fs/cifs/file.c in the
    Linux kernel through 3.13.5 does not properly handle
    uncached write operations that copy fewer than the
    requested number of bytes, which allows local users to
    obtain sensitive information from kernel memory, cause
    a denial of service (memory corruption and system
    crash), or possibly gain privileges via a writev system
    call with a crafted pointer.(CVE-2014-0069i1/4%0

  - A flaw was found in the Linux kernel's implementation
    of XFS file attributes. Two memory leaks were detected
    in xfs_attr_shortform_list and xfs_attr3_leaf_list_int
    when running a docker container backed by xfs/overlay2.
    A dedicated attacker could possible exhaust all memory
    and create a denial of service
    situation.(CVE-2016-9685i1/4%0

  - Multiple integer overflows in the MDSS driver for the
    Linux kernel 3.x, as used in Qualcomm Innovation Center
    (QuIC) Android contributions for MSM devices and other
    products, allow attackers to cause a denial of service
    or possibly have unspecified other impact via a large
    size value, related to mdss_compat_utils.c, mdss_fb.c,
    and mdss_rotator.c.(CVE-2016-5344i1/4%0

  - kernel/bpf/verifier.c in the Linux kernel through
    4.14.8 ignores unreachable code, even though it would
    still be processed by JIT compilers. This behavior,
    also considered an improper branch-pruning logic issue,
    could possibly be used by local users for denial of
    service.(CVE-2017-17862i1/4%0

  - A flaw was found in the Linux kernel's implementation
    of the SCTP protocol. A remote attacker could trigger
    an out-of-bounds read with an offset of up to 64kB
    potentially causing the system to
    crash.(CVE-2016-9555i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1516
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?161cd16f");
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
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
