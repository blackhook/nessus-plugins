#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5708.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137173);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2017-1000370",
    "CVE-2017-1000371",
    "CVE-2018-18281",
    "CVE-2019-12819",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-19057",
    "CVE-2019-19524",
    "CVE-2019-19528",
    "CVE-2019-19537",
    "CVE-2019-20636",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-11668"
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2020-5708)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2020-5708 advisory.

  - Since Linux kernel version 3.2, the mremap() syscall performs TLB flushes after dropping pagetable locks.
    If a syscall such as ftruncate() removes entries from the pagetables of a task that is in the middle of
    mremap(), a stale TLB entry can remain for a short time that permits access to a physical page after it
    has been released back to the page allocator and reused. This is fixed in the following kernel versions:
    4.9.135, 4.14.78, 4.18.16, 4.19. (CVE-2018-18281)

  - An issue was discovered in the Linux kernel before 5.6.1. drivers/media/usb/gspca/ov519.c allows NULL
    pointer dereferences in ov511_mode_init_regs and ov518_mode_init_regs when there are zero endpoints, aka
    CID-998912346c0d. (CVE-2020-11608)

  - An issue was discovered in the stv06xx subsystem in the Linux kernel before 5.6.1.
    drivers/media/usb/gspca/stv06xx/stv06xx.c and drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c mishandle
    invalid descriptors, as demonstrated by a NULL pointer dereference, aka CID-485b06aadb93. (CVE-2020-11609)

  - In the Linux kernel before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink camera USB
    driver) mishandles invalid descriptors, aka CID-a246b4d54770. (CVE-2020-11668)

  - The offset2lib patch as used in the Linux Kernel contains a vulnerability that allows a PIE binary to be
    execve()'ed with 1GB of arguments or environmental strings then the stack occupies the address 0x80000000
    and the PIE binary is mapped above 0x40000000 nullifying the protection of the offset2lib patch. This
    affects Linux Kernel version 4.11.5 and earlier. This is a different issue than CVE-2017-1000371. This
    issue appears to be limited to i386 based systems. (CVE-2017-1000370)

  - A stack-based buffer overflow was found in the Linux kernel, version kernel-2.6.32, in Marvell WiFi chip
    driver. An attacker is able to cause a denial of service (system crash) or, possibly execute arbitrary
    code, when a STA works in IBSS mode (allows connecting stations together without the use of an AP) and
    connects to another STA. (CVE-2019-14897)

  - In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9. (CVE-2019-19524)

  - In the Linux kernel before 5.3.7, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/misc/iowarrior.c driver, aka CID-edc4746f253d. (CVE-2019-19528)

  - In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka CID-303911cfc5b9. This affects
    drivers/usb/core/file.c. (CVE-2019-19537)

  - In the Linux kernel before 5.4.12, drivers/input/input.c has out-of-bounds writes via a crafted keycode
    table, as demonstrated by input_set_keycode, aka CID-cb222aed03d7. (CVE-2019-20636)

  - An issue was discovered in the Linux kernel before 5.0. The function __mdiobus_register() in
    drivers/net/phy/mdio_bus.c calls put_device(), which will trigger a fixed_mdio_bus_init use-after-free.
    This will cause a denial of service. (CVE-2019-12819)

  - Two memory leaks in the mwifiex_pcie_init_evt_ring() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux kernel through 5.3.11 allow attackers to cause a
    denial of service (memory consumption) by triggering mwifiex_map_pci_memory() failures, aka
    CID-d10dcb615c8e. (CVE-2019-19057)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5708.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14896");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6 / 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.1.12-124.39.5.el6uek', '4.1.12-124.39.5.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2020-5708');
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
    {'reference':'kernel-uek-4.1.12-124.39.5.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.39.5.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.39.5.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.39.5.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.39.5.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.39.5.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'kernel-uek-4.1.12-124.39.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.39.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.39.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.39.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.39.5.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.39.5.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
