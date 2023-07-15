#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2014-3096.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79735);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2014-1739",
    "CVE-2014-3181",
    "CVE-2014-3184",
    "CVE-2014-3185",
    "CVE-2014-3535",
    "CVE-2014-3601",
    "CVE-2014-3611",
    "CVE-2014-3645",
    "CVE-2014-3646",
    "CVE-2014-3673",
    "CVE-2014-3687",
    "CVE-2014-4014",
    "CVE-2014-4171",
    "CVE-2014-4653",
    "CVE-2014-4654",
    "CVE-2014-4655"
  );
  script_bugtraq_id(
    67988,
    68048,
    68157,
    68162,
    68164,
    69489,
    69721,
    69768,
    69779,
    69781,
    70743,
    70745,
    70746,
    70766,
    70883
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2014-3096)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2014-3096 advisory.

  - The report_fixup functions in the HID subsystem in the Linux kernel before 3.16.2 might allow physically
    proximate attackers to cause a denial of service (out-of-bounds write) via a crafted device that provides
    a small report descriptor, related to (1) drivers/hid/hid-cherry.c, (2) drivers/hid/hid-kye.c, (3)
    drivers/hid/hid-lg.c, (4) drivers/hid/hid-monterey.c, (5) drivers/hid/hid-petalynx.c, and (6)
    drivers/hid/hid-sunplus.c. (CVE-2014-3184)

  - The capabilities implementation in the Linux kernel before 3.14.8 does not properly consider that
    namespaces are inapplicable to inodes, which allows local users to bypass intended chmod restrictions by
    first creating a user namespace, as demonstrated by setting the setgid bit on a file with group ownership
    of root. (CVE-2014-4014)

  - The media_device_enum_entities function in drivers/media/media-device.c in the Linux kernel before 3.14.6
    does not initialize a certain data structure, which allows local users to obtain sensitive information
    from kernel memory by leveraging /dev/media0 read access for a MEDIA_IOC_ENUM_ENTITIES ioctl call.
    (CVE-2014-1739)

  - mm/shmem.c in the Linux kernel through 3.15.1 does not properly implement the interaction between range
    notification and hole punching, which allows local users to cause a denial of service (i_mutex hold) by
    using the mmap system call to access a hole, as demonstrated by interfering with intended shmem activity
    by blocking completion of (1) an MADV_REMOVE madvise call or (2) an FALLOC_FL_PUNCH_HOLE fallocate call.
    (CVE-2014-4171)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-3096.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4014");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-55.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-55.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['3.8.13-55.el6uek', '3.8.13-55.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2014-3096');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.8';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'dtrace-modules-3.8.13-55.el6uek-0.4.3-4.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-55.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-55.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-55.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-55.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-55.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-55.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'},
    {'reference':'dtrace-modules-3.8.13-55.el7uek-0.4.3-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-55.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-55.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-55.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-55.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-55.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-55.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-3.8.13-55.el6uek / dtrace-modules-3.8.13-55.el7uek / kernel-uek / etc');
}
