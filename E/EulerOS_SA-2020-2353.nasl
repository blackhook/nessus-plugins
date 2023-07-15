#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142240);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2014-8181",
    "CVE-2019-20810",
    "CVE-2019-20811",
    "CVE-2019-20812",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10769",
    "CVE-2020-12888",
    "CVE-2020-13974",
    "CVE-2020-14314",
    "CVE-2020-14331",
    "CVE-2020-14386",
    "CVE-2020-15393",
    "CVE-2020-16166",
    "CVE-2020-25211",
    "CVE-2020-25212",
    "CVE-2020-25284",
    "CVE-2020-25285",
    "CVE-2020-25643"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2020-2353)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):A flaw was found in the
    Linux kernel's implementation of the invert video code
    on VGA consoles when a local attacker attempts to
    resize the console, calling an ioctl VT_RESIZE, which
    causes an out-of-bounds write to occur. This flaw
    allows a local user with access to the VGA console to
    crash the system, potentially escalating their
    privileges on the system. The highest threat from this
    vulnerability is to data confidentiality and integrity
    as well as system availability.(CVE-2020-14331)A flaw
    was found in the HDLC_PPP module of the Linux kernel in
    versions before 5.9-rc7. Memory corruption and a read
    overflow is caused by improper input validation in the
    ppp_cp_parse_cr function which can cause the system to
    crash or cause a denial of service. The highest threat
    from this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-25643)A memory out-of-bounds
    read flaw was found in the Linux kernel before 5.9-rc2
    with the ext3/ext4 file system, in the way it accesses
    a directory with broken indexing. This flaw allows a
    local user to crash the system if the directory exists.
    The highest threat from this vulnerability is to system
    availability.(CVE-2020-14314)A TOCTOU mismatch in the
    NFS client code in the Linux kernel before 5.8.3 could
    be used by local attackers to corrupt memory or
    possibly have unspecified other impact because a size
    check is in fs/ nfs/ nfs4proc.c instead of fs/ nfs/
    nfs4xdr.c, aka CID-b4487b935452.(CVE-2020-25212)The rbd
    block device driver in drivers/block/rbd.c in the Linux
    kernel through 5.8.9 used incomplete permission
    checking for access to rbd devices, which could be
    leveraged by local attackers to map or unmap rbd block
    devices, aka CID-f44d04e696fe.(CVE-2020-25284)A race
    condition between hugetlb sysctl handlers in
    mm/hugetlb.c in the Linux kernel before 5.8.8 could be
    used by local attackers to corrupt memory, cause a NULL
    pointer dereference, or possibly have unspecified other
    impact, aka CID-17743798d812.(CVE-2020-25285)A flaw was
    found in the Linux kernel before 5.9-rc4. Memory
    corruption can be exploited to gain root privileges
    from unprivileged processes. The highest threat from
    this vulnerability is to data confidentiality and
    integrity.(CVE-2020-14386)In the Linux kernel through
    5.8.7, local attackers able to inject conntrack netlink
    configuration could overflow a local buffer, causing
    crashes or triggering use of incorrect protocol numbers
    in ctnetlink_parse_tuple_filter in net/ netfilter/
    nf_conntrack_netlink.c, aka
    CID-1cc5ef91d2ff.(CVE-2020-25211)The VFIO PCI driver in
    the Linux kernel through 5.6.13 mishandles attempts to
    access disabled memory space.(CVE-2020-12888)The kernel
    in Red Hat Enterprise Linux 7 and MRG-2 does not clear
    garbage data for SG_IO buffer, which may leaking
    sensitive information to userspace.(CVE-2014-8181)A
    flaw was found in the Linux kernels SELinux LSM hook
    implementation before version 5.7, where it incorrectly
    assumed that an skb would only contain a single netlink
    message. The hook would incorrectly only validate the
    first netlink message in the skb and allow or deny the
    rest of the messages within the skb with the granted
    permission without further
    processing.(CVE-2020-10751)The Linux kernel through
    5.7.11 allows remote attackers to make observations
    that help to obtain sensitive information about the
    internal state of the network RNG, aka
    CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and
    kernel/time/timer.c.(CVE-2020-16166)A buffer over-read
    flaw was found in RH kernel versions before 5.0 in
    crypto_authenc_extractkeys in crypto/authenc.c in the
    IPsec Cryptographic algorithm's module, authenc. When a
    payload longer than 4 bytes, and is not following
    4-byte alignment boundary guidelines, it causes a
    buffer over-read threat, leading to a system crash.
    This flaw allows a local attacker with user privileges
    to cause a denial of service.(CVE-2020-10769)In the
    Linux kernel through 5.7.6, usbtest_disconnect in
    drivers/usb/misc/usbtest.c has a memory leak, aka
    CID-28ebeb8db770.(CVE-2020-15393)An issue was
    discovered in the Linux kernel through 5.7.1.
    drivers/tty/vt/keyboard.c has an integer overflow if
    k_ascii is called several times in a row, aka
    CID-b86dab054059.(CVE-2020-13974)go7007_snd_init in
    drivers/media/usb/go7007/snd-go7007.c in the Linux
    kernel before 5.6 does not call snd_card_free for a
    failure path, which causes a memory leak, aka
    CID-9453264ef586.(CVE-2019-20810)An issue was
    discovered in the Linux kernel before 5.0.6. In
    rx_queue_add_kobject() and netdev_queue_add_kobject()
    in net/core/ net-sysfs.c, a reference count is
    mishandled, aka CID-a3e23f719f5c.(CVE-2019-20811)An
    issue was discovered in the Linux kernel before 5.4.7.
    The prb_calc_retire_blk_tmo() function in
    net/packet/af_packet.c can result in a denial of
    service (CPU consumption and soft lockup) in a certain
    failure case involving TPACKET_V3, aka
    CID-b43d1f9f7067.(CVE-2019-20812)A flaw was found in
    the Linux kernel's implementation of Userspace core
    dumps. This flaw allows an attacker with a local
    account to crash a trivial program and exfiltrate
    private kernel data.(CVE-2020-10732)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2353
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae382c7d");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.62.59.83.h243",
        "kernel-debug-3.10.0-327.62.59.83.h243",
        "kernel-debug-devel-3.10.0-327.62.59.83.h243",
        "kernel-debuginfo-3.10.0-327.62.59.83.h243",
        "kernel-debuginfo-common-x86_64-3.10.0-327.62.59.83.h243",
        "kernel-devel-3.10.0-327.62.59.83.h243",
        "kernel-headers-3.10.0-327.62.59.83.h243",
        "kernel-tools-3.10.0-327.62.59.83.h243",
        "kernel-tools-libs-3.10.0-327.62.59.83.h243",
        "perf-3.10.0-327.62.59.83.h243",
        "python-perf-3.10.0-327.62.59.83.h243"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
