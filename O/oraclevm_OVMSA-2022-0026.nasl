#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were
# extracted from OracleVM Security Advisory OVMSA-2022-0026.
##

include('compat.inc');

if (description)
{
  script_id(166048);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_cve_id(
    "CVE-2017-7472",
    "CVE-2017-16537",
    "CVE-2017-18270",
    "CVE-2018-9422",
    "CVE-2020-12770",
    "CVE-2020-14390",
    "CVE-2021-30002",
    "CVE-2021-43976",
    "CVE-2021-45486",
    "CVE-2022-0850",
    "CVE-2022-1184",
    "CVE-2022-2503",
    "CVE-2022-2964",
    "CVE-2022-3028",
    "CVE-2022-36879"
  );

  script_name(english:"OracleVM 3.4 : kernel-uek (OVMSA-2022-0026)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address security updates:

  - The imon_probe function in drivers/media/rc/imon.c in the Linux kernel through 4.13.11 allows local users
    to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified
    other impact via a crafted USB device. (CVE-2017-16537)

  - In the Linux kernel before 4.13.5, a local user could create keyrings for other users via keyctl commands,
    setting unwanted defaults or causing a denial of service. (CVE-2017-18270)

  - The KEYS subsystem in the Linux kernel before 4.10.13 allows local users to cause a denial of service
    (memory consumption) via a series of KEY_REQKEY_DEFL_THREAD_KEYRING keyctl_set_reqkey_keyring calls.
    (CVE-2017-7472)

  - In get_futex_key of futex.c, there is a use-after-free due to improper locking. This could lead to local
    escalation of privilege with no additional privileges needed. User interaction is not needed for
    exploitation. Product: Android Versions: Android kernel Android ID: A-74250718 References: Upstream
    kernel. (CVE-2018-9422)

  - An issue was discovered in the Linux kernel through 5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka CID-83c6f2390040. (CVE-2020-12770)

  - A flaw was found in the Linux kernel in versions before 5.9-rc6. When changing screen size, an out-of-
    bounds memory write can occur leading to memory corruption or a denial of service. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled out. (CVE-2020-14390)

  - An issue was discovered in the Linux kernel before 5.11.3 when a webcam device exists. video_usercopy in
    drivers/media/v4l2-core/v4l2-ioctl.c has a memory leak for large arguments, aka CID-fb18802a338b.
    (CVE-2021-30002)

  - In the Linux kernel through 5.15.2, mwifiex_usb_recv in drivers/net/wireless/marvell/mwifiex/usb.c allows
    an attacker (who can connect a crafted USB device) to cause a denial of service (skb_over_panic).
    (CVE-2021-43976)

  - In the IPv4 implementation in the Linux kernel before 5.12.4, net/ipv4/route.c has an information leak
    because the hash table is very small. (CVE-2021-45486)

  - A vulnerability was found in linux kernel, where an information leak occurs via ext4_extent_header to
    userspace. (CVE-2022-0850)

  - A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-
    component. This flaw allows a local attacker with a user privilege to cause a denial of service.
    (CVE-2022-1184)

  - Dm-verity is used for extending root-of-trust to root filesystems. LoadPin builds on this property to
    restrict module/firmware loads to just the trusted root filesystem. Device-mapper table reloads currently
    allow users with root privileges to switch out the target with an equivalent dm-linear target and bypass
    verification till reboot. This allows root to bypass LoadPin and can be used to load untrusted and
    unverified kernel modules and firmware, which implies arbitrary kernel execution and persistence for
    peripherals that do not verify firmware updates. We recommend upgrading past commit
    4caae58406f8ceb741603eee460d79bacca9b1b5 (CVE-2022-2503)

  - A flaw was found in the Linux kernel's driver for the ASIX AX88179_178A-based USB 2.0/3.0 Gigabit Ethernet
    Devices. The vulnerability contains multiple out-of-bounds reads and possible out-of-bounds writes.
    (CVE-2022-2964)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - An issue was discovered in the Linux kernel through 5.18.14. xfrm_expand_policies in
    net/xfrm/xfrm_policy.c can cause a refcount to be dropped twice. (CVE-2022-36879)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2017-16537.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2017-18270.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2017-7472.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2018-9422.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-12770.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-14390.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-30002.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-43976.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-45486.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2022-0850.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2022-1184.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2022-2503.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2022-2964.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2022-3028.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2022-36879.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/OVMSA-2022-0026.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek / kernel-uek-firmware packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9422");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2964");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.1.12-124.67.3.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for OVMSA-2022-0026');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.1';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-4.1.12-124.67.3.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.67.3.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'OVS' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-firmware');
}
