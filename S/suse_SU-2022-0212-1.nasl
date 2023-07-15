#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0212-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157221);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2022-23302", "CVE-2022-23305", "CVE-2022-23307");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0212-1");

  script_name(english:"SUSE SLES12 Security Update : log4j (SUSE-SU-2022:0212-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0212-1 advisory.

  - JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the attacker
    has write access to the Log4j configuration or if the configuration references an LDAP service the
    attacker has access to. The attacker can provide a TopicConnectionFactoryBindingName configuration causing
    JMSSink to perform JNDI requests that result in remote code execution in a similar fashion to
    CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically configured to use JMSSink, which
    is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2
    as it addresses numerous other issues from the previous versions. (CVE-2022-23302)

  - By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the
    values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be
    included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or
    headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue
    only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default.
    Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized
    SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of
    life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the
    previous versions. (CVE-2022-23305)

  - CVE-2020-9493 identified a deserialization issue that was present in Apache Chainsaw. Prior to Chainsaw
    V2.0 Chainsaw was a component of Apache Log4j 1.2.x where the same issue exists. (CVE-2022-23307)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194844");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-January/010124.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d19f84f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23305");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23307");
  script_set_attribute(attribute:"solution", value:
"Update the affected log4j and / or log4j-manual packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23307");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:log4j-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'log4j-1.2.15-126.9.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'log4j-1.2.15-126.9.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'log4j-1.2.15-126.9.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'log4j-manual-1.2.15-126.9.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'log4j-1.2.15-126.9.1', 'sp':'2', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'log4j-1.2.15-126.9.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'log4j-1.2.15-126.9.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'log4j / log4j-manual');
}
