#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:3433.
##

include('compat.inc');

if (description)
{
  script_id(177618);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

  script_cve_id("CVE-2023-28204", "CVE-2023-32373");
  script_xref(name:"RLSA", value:"2023:3433");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/12");

  script_name(english:"Rocky Linux 8 : webkit2gtk3 (RLSA-2023:3433)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2023:3433 advisory.

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in watchOS 9.5,
    iOS 15.7.6 and iPadOS 15.7.6, macOS Ventura 13.4, Safari 16.5, tvOS 16.5, iOS 16.5 and iPadOS 16.5.
    Processing web content may disclose sensitive information. Apple is aware of a report that this issue may
    have been actively exploited. (CVE-2023-28204)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 9.5,
    iOS 15.7.6 and iPadOS 15.7.6, macOS Ventura 13.4, Safari 16.5, tvOS 16.5, iOS 16.5 and iPadOS 16.5.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited. (CVE-2023-32373)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:3433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2209208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2209214");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32373");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'webkit2gtk3-2.38.5-1.el8_8.4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.38.5-1.el8_8.4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.38.5-1.el8_8.4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debuginfo-2.38.5-1.el8_8.4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debuginfo-2.38.5-1.el8_8.4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debuginfo-2.38.5-1.el8_8.4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debugsource-2.38.5-1.el8_8.4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debugsource-2.38.5-1.el8_8.4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debugsource-2.38.5-1.el8_8.4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.38.5-1.el8_8.4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.38.5-1.el8_8.4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.38.5-1.el8_8.4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-debuginfo-2.38.5-1.el8_8.4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-debuginfo-2.38.5-1.el8_8.4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-debuginfo-2.38.5-1.el8_8.4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.38.5-1.el8_8.4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.38.5-1.el8_8.4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.38.5-1.el8_8.4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.38.5-1.el8_8.4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.38.5-1.el8_8.4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.38.5-1.el8_8.4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.38.5-1.el8_8.4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.38.5-1.el8_8.4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.38.5-1.el8_8.4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.38.5-1.el8_8.4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.38.5-1.el8_8.4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.38.5-1.el8_8.4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkit2gtk3 / webkit2gtk3-debuginfo / webkit2gtk3-debugsource / etc');
}
