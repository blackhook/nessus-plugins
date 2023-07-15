#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124809);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2014-9644",
    "CVE-2014-9710",
    "CVE-2014-9715",
    "CVE-2014-9728",
    "CVE-2014-9729",
    "CVE-2014-9730",
    "CVE-2014-9731",
    "CVE-2014-9892",
    "CVE-2014-9895",
    "CVE-2014-9900",
    "CVE-2014-9904",
    "CVE-2014-9914",
    "CVE-2014-9922",
    "CVE-2014-9940",
    "CVE-2015-0239",
    "CVE-2015-0274",
    "CVE-2015-0275",
    "CVE-2015-1333",
    "CVE-2015-1420",
    "CVE-2015-1421",
    "CVE-2015-1465",
    "CVE-2015-1573",
    "CVE-2015-1593"
  );
  script_bugtraq_id(
    72320,
    72356,
    72357,
    72435,
    72552,
    72607,
    72842,
    73156,
    73308,
    73953,
    74964,
    75001,
    75139
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1485)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A flaw was found in the way the Linux kernel's Crypto
    subsystem handled automatic loading of kernel modules.
    A local user could use this flaw to load any installed
    kernel module, and thus increase the attack surface of
    the running kernel.(CVE-2014-9644)

  - The Btrfs implementation in the Linux kernel before
    3.19 does not ensure that the visible xattr state is
    consistent with a requested replacement, which allows
    local users to bypass intended ACL settings and gain
    privileges via standard filesystem operations (1)
    during an xattr-replacement time window, related to a
    race condition, or (2) after an xattr-replacement
    attempt that fails because the data does not
    fit.(CVE-2014-9710)

  - An integer overflow flaw was found in the way the Linux
    kernel's netfilter connection tracking implementation
    loaded extensions. An attacker on a local network could
    potentially send a sequence of specially crafted
    packets that would initiate the loading of a large
    number of extensions, causing the targeted system in
    that network to crash.(CVE-2014-9715)

  - A symlink size validation was missing in Linux kernels
    built with UDF file system (CONFIG_UDF_FS) support,
    allowing the corruption of kernel memory. An attacker
    able to mount a corrupted/malicious UDF file system
    image could cause the kernel to crash.(CVE-2014-9728)

  - A symlink size validation was missing in Linux kernels
    built with UDF file system (CONFIG_UDF_FS) support,
    allowing the corruption of kernel memory. An attacker
    able to mount a corrupted/malicious UDF file system
    image could cause the kernel to crash.(CVE-2014-9729)

  - A symlink size validation was missing in Linux kernels
    built with UDF file system (CONFIG_UDF_FS) support,
    allowing the corruption of kernel memory. An attacker
    able to mount a corrupted/malicious UDF file system
    image could cause the kernel to crash.(CVE-2014-9730)

  - A path length checking flaw was found in Linux kernels
    built with UDF file system (CONFIG_UDF_FS) support. An
    attacker able to mount a corrupted/malicious UDF file
    system image could use this flaw to leak kernel memory
    to user-space.(CVE-2014-9731)

  - The snd_compr_tstamp function in
    sound/core/compress_offload.c in the Linux kernel
    through 4.7, as used in Android before 2016-08-05 on
    Nexus 5 and 7 (2013) devices, does not properly
    initialize a timestamp data structure, which allows
    attackers to obtain sensitive information via a crafted
    application, aka Android internal bug 28770164 and
    Qualcomm internal bug CR568717.(CVE-2014-9892)

  - drivers/media/media-device.c in the Linux kernel before
    3.11, as used in Android before 2016-08-05 on Nexus 5
    and 7 (2013) devices, does not properly initialize
    certain data structures, which allows local users to
    obtain sensitive information via a crafted application,
    aka Android internal bug 28750150 and Qualcomm internal
    bug CR570757, a different vulnerability than
    CVE-2014-1739.(CVE-2014-9895)

  - The ethtool_get_wol function in net/core/ethtool.c in
    the Linux kernel through 4.7, as used in Android before
    2016-08-05 on Nexus 5 and 7 (2013) devices, does not
    initialize a certain data structure, which allows local
    users to obtain sensitive information via a crafted
    application, aka Android internal bug 28803952 and
    Qualcomm internal bug CR570754.(CVE-2014-9900)

  - The snd_compress_check_input function in
    sound/core/compress_offload.c in the ALSA subsystem in
    the Linux kernel before 3.17 does not properly check
    for an integer overflow, which allows local users to
    cause a denial of service (insufficient memory
    allocation) or possibly have unspecified other impact
    via a crafted SNDRV_COMPRESS_SET_PARAMS ioctl
    call.(CVE-2014-9904)

  - A race condition in the ip4_datagram_release_cb
    function in net/ipv4/datagram.c in the Linux kernel
    allows local users to gain privileges or cause a denial
    of service (use-after-free) by leveraging incorrect
    expectations about locking during multithreaded access
    to internal data structures for IPv4 UDP
    sockets.(CVE-2014-9914)

  - A flaw was discovered in the way the kernel allows
    stackable filesystems to overlay. A local attacker who
    is able to mount filesystems can abuse this flaw to
    escalate privileges.(CVE-2014-9922)

  - The regulator_ena_gpio_free function in
    drivers/regulator/core.c in the Linux kernel allows
    local users to gain privileges or cause a denial of
    service (use-after-free) via a crafted
    application.(CVE-2014-9940)

  - It was found that the Linux kernel KVM subsystem's
    sysenter instruction emulation was not sufficient. An
    unprivileged guest user could use this flaw to escalate
    their privileges by tricking the hypervisor to emulate
    a SYSENTER instruction in 16-bit mode, if the guest OS
    did not initialize the SYSENTER model-specific
    registers (MSRs). Note: Certified guest operating
    systems for Red Hat Enterprise Linux with KVM do
    initialize the SYSENTER MSRs and are thus not
    vulnerable to this issue when running on a KVM
    hypervisor.(CVE-2015-0239)

  - A flaw was found in the way the Linux kernel's XFS file
    system handled replacing of remote attributes under
    certain conditions. A local user with access to XFS
    file system mount could potentially use this flaw to
    escalate their privileges on the system.(CVE-2015-0274)

  - A flaw was found in the way the Linux kernel's ext4
    file system handled the 'page size i1/4z block size'
    condition when the fallocate zero range functionality
    was used. A local attacker could use this flaw to crash
    the system.(CVE-2015-0275)

  - It was found that the Linux kernel's keyring
    implementation would leak memory when adding a key to a
    keyring via the add_key() function. A local attacker
    could use this flaw to exhaust all available memory on
    the system.(CVE-2015-1333)

  - Race condition in the handle_to_path function in
    fs/fhandle.c in the Linux kernel through 3.19.1 allows
    local users to bypass intended size restrictions and
    trigger read operations on additional memory locations
    by changing the handle_bytes value of a file handle
    during the execution of this function.(CVE-2015-1420)

  - A use-after-free flaw was found in the way the Linux
    kernel's SCTP implementation handled authentication key
    reference counting during INIT collisions. A remote
    attacker could use this flaw to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2015-1421)

  - The IPv4 implementation in the Linux kernel before
    3.18.8 does not properly consider the length of the
    Read-Copy Update (RCU) grace period for redirecting
    lookups in the absence of caching, which allows remote
    attackers to cause a denial of service (memory
    consumption or system crash) via a flood of
    packets.(CVE-2015-1465)

  - A flaw was found in the way the nft_flush_table()
    function of the Linux kernel's netfilter tables
    implementation flushed rules that were referencing
    deleted chains. A local user who has the CAP_NET_ADMIN
    capability could use this flaw to crash the
    system.(CVE-2015-1573)

  - An integer overflow flaw was found in the way the Linux
    kernel randomized the stack for processes on certain
    64-bit architecture systems, such as x86-64, causing
    the stack entropy to be reduced by four.(CVE-2015-1593)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1485
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56c41fa7");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
