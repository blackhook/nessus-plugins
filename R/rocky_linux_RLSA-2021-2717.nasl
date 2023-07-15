#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:2717.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157754);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2021-33910");
  script_xref(name:"RLSA", value:"2021:2717");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"Rocky Linux 8 : systemd (RLSA-2021:2717)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2021:2717 advisory.

  - basic/unit-name.c in systemd prior to 246.15, 247.8, 248.5, and 249.1 has a Memory Allocation with an
    Excessive Size Value (involving strdupa and alloca for a pathname controlled by a local attacker) that
    results in an operating system crash. (CVE-2021-33910)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:2717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1970887");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33910");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-container-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-journal-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-pam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:systemd-udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'systemd-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-239-45.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-45.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-debuginfo-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-debuginfo-239-45.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-debuginfo-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debuginfo-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debuginfo-239-45.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debuginfo-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debugsource-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debugsource-239-45.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-debugsource-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-45.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-debuginfo-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-debuginfo-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-45.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-debuginfo-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-debuginfo-239-45.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-debuginfo-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-debuginfo-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-debuginfo-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-debuginfo-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-debuginfo-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-debuginfo-239-45.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-debuginfo-239-45.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'systemd / systemd-container / systemd-container-debuginfo / etc');
}
