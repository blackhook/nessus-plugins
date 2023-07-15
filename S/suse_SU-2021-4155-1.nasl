#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:4155-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156285);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2020-17507", "CVE-2021-3481");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:4155-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libqt4 (SUSE-SU-2021:4155-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:4155-1 advisory.

  - An issue was discovered in Qt through 5.12.9, and 5.13.x through 5.15.x before 5.15.1. read_xbm_body in
    gui/image/qxbmhandler.cpp has a buffer over-read. (CVE-2020-17507)

  - qt: Out of bounds read in function QRadialFetchSimd from crafted svg file (CVE-2021-3481)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184783");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009927.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0532df3f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-17507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3481");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17507");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-devel-doc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-qt3support-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-x11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + sp);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'libqt4-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-qt3support-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-qt3support-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-sql-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-sql-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-sql-mysql-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-sql-sqlite-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-x11-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-x11-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'qt4-x11-tools-4.8.7-8.16.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libqt4-devel-4.8.7-8.16.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-devel-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-devel-doc-4.8.7-8.16.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-devel-doc-4.8.7-8.16.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-devel-doc-data-4.8.7-8.16.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-devel-doc-data-4.8.7-8.16.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-linguist-4.8.7-8.16.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-linguist-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-private-headers-devel-4.8.7-8.16.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-private-headers-devel-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-sql-postgresql-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-sql-postgresql-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-sql-postgresql-4.8.7-8.16.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-sql-postgresql-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-sql-unixODBC-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-sql-unixODBC-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-sql-unixODBC-4.8.7-8.16.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-sql-unixODBC-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libqt4-sql-mysql-32bit-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-mysql-32bit-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-postgresql-32bit-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-postgresql-32bit-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-postgresql-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-postgresql-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-sqlite-32bit-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-sqlite-32bit-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-unixODBC-32bit-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-unixODBC-32bit-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-unixODBC-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-sql-unixODBC-4.8.7-8.16.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-12.5'},
    {'reference':'libqt4-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libqt4-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libqt4-qt3support-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libqt4-qt3support-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libqt4-sql-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libqt4-sql-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libqt4-sql-mysql-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libqt4-sql-sqlite-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libqt4-x11-32bit-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libqt4-x11-4.8.7-8.16.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'qt4-x11-tools-4.8.7-8.16.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libqt4 / libqt4-32bit / libqt4-devel / libqt4-devel-doc / etc');
}
