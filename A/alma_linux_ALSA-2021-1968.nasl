#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:1968.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157470);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2019-16168",
    "CVE-2020-13434",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632"
  );
  script_xref(name:"ALSA", value:"2021:1968");
  script_xref(name:"IAVA", value:"2020-A-0021-S");
  script_xref(name:"IAVA", value:"2020-A-0358-S");

  script_name(english:"AlmaLinux 8 : mingw packages (ALSA-2021:1968)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2021:1968 advisory.

  - In SQLite through 3.29.0, whereLoopAddBtreeIndex in sqlite3.c can crash a browser or other application
    because of missing validation of a sqlite_stat1 sz field, aka a severe division by zero in the query
    planner. (CVE-2019-16168)

  - SQLite through 3.32.0 has an integer overflow in sqlite3_str_vappendf in printf.c. (CVE-2020-13434)

  - ext/fts3/fts3.c in SQLite before 3.32.0 has a use-after-free in fts3EvalNextRow, related to the snippet
    feature. (CVE-2020-13630)

  - SQLite before 3.32.0 allows a virtual table to be renamed to the name of one of its shadow tables, related
    to alter.c and build.c. (CVE-2020-13631)

  - ext/fts3/fts3_snippet.c in SQLite before 3.32.0 has a NULL pointer dereference via a crafted matchinfo()
    query. (CVE-2020-13632)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-1968.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13630");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw-binutils-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw-filesystem-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw32-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw32-bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw32-bzip2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw32-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw32-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw32-sqlite-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw64-bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw64-bzip2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw64-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw64-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mingw64-sqlite-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'mingw-binutils-generic-2.30-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw-filesystem-base-104-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw32-binutils-2.30-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw32-bzip2-1.0.6-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw32-bzip2-static-1.0.6-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw32-filesystem-104-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw32-sqlite-3.26.0.0-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw32-sqlite-static-3.26.0.0-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw64-binutils-2.30-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw64-bzip2-1.0.6-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw64-bzip2-static-1.0.6-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw64-filesystem-104-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw64-sqlite-3.26.0.0-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mingw64-sqlite-static-3.26.0.0-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mingw-binutils-generic / mingw-filesystem-base / mingw32-binutils / etc');
}
