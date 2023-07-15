#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2892-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152944);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/01");

  script_cve_id("CVE-2020-28200", "CVE-2021-29157");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2892-1");

  script_name(english:"SUSE SLES15 Security Update : dovecot23 (SUSE-SU-2021:2892-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:2892-1 advisory.

  - The Sieve engine in Dovecot before 2.3.15 allows Uncontrolled Resource Consumption, as demonstrated by a
    situation with a complex regular expression for the regex extension. (CVE-2020-28200)

  - Dovecot before 2.3.15 allows ../ Path Traversal. An attacker with access to the local filesystem can trick
    OAuth2 authentication into using an HS256 validation key from an attacker-controlled location. This occurs
    during use of local JWT validation with the posix fs driver. (CVE-2021-29157)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187420");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-August/009374.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be579a44");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29157");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29157");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-squat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'dovecot23-2.3.15-58.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.2'},
    {'reference':'dovecot23-backend-mysql-2.3.15-58.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.2'},
    {'reference':'dovecot23-backend-pgsql-2.3.15-58.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.2'},
    {'reference':'dovecot23-backend-sqlite-2.3.15-58.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.2'},
    {'reference':'dovecot23-devel-2.3.15-58.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.2'},
    {'reference':'dovecot23-fts-2.3.15-58.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.2'},
    {'reference':'dovecot23-fts-lucene-2.3.15-58.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.2'},
    {'reference':'dovecot23-fts-solr-2.3.15-58.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.2'},
    {'reference':'dovecot23-fts-squat-2.3.15-58.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.2'},
    {'reference':'dovecot23-2.3.15-58.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'dovecot23-backend-mysql-2.3.15-58.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'dovecot23-backend-pgsql-2.3.15-58.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'dovecot23-backend-sqlite-2.3.15-58.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'dovecot23-devel-2.3.15-58.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'dovecot23-fts-2.3.15-58.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'dovecot23-fts-lucene-2.3.15-58.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'dovecot23-fts-solr-2.3.15-58.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'dovecot23-fts-squat-2.3.15-58.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dovecot23 / dovecot23-backend-mysql / dovecot23-backend-pgsql / etc');
}
