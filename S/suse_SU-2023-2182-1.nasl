#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2182-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(175415);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/12");

  script_cve_id("CVE-2022-41715", "CVE-2022-46146");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2182-1");

  script_name(english:"openSUSE 15 Security Update : SUSE Manager Client Tools (SUSE-SU-2023:2182-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
SUSE-SU-2023:2182-1 advisory.

  - Programs which compile regular expressions from untrusted sources may be vulnerable to memory exhaustion
    or denial of service. The parsed regexp representation is linear in the size of the input, but in some
    cases the constant factor can be as high as 40,000, making relatively small regexps consume much larger
    amounts of memory. After fix, each regexp being parsed is limited to a 256 MB memory footprint. Regular
    expressions whose representation would use more space than that are rejected. Normal use of regular
    expressions is unaffected. (CVE-2022-41715)

  - Prometheus Exporter Toolkit is a utility package to build exporters. Prior to versions 0.7.2 and 0.8.2, if
    someone has access to a Prometheus web.yml file and users' bcrypted passwords, they can bypass security by
    poisoning the built-in authentication cache. Versions 0.7.2 and 0.8.2 contain a fix for the issue. There
    is no workaround, but attacker must have access to the hashed password to use this functionality.
    (CVE-2022-46146)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209113");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-May/029371.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46146");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-github-prometheus-promu, prometheus-blackbox_exporter and / or prometheus-postgres_exporter
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46146");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^SUSE") audit(AUDIT_OS_NOT, "openSUSE");
var os_ver = pregmatch(pattern: "^(SUSE[\d.]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'openSUSE 15', 'openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE (' + os_ver + ')', cpu);

var pkgs = [
    {'reference':'golang-github-prometheus-promu-0.14.0-150000.3.12.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'prometheus-blackbox_exporter-0.19.0-150000.1.17.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'prometheus-postgres_exporter-0.10.1-150000.1.11.4', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-prometheus-promu / prometheus-blackbox_exporter / etc');
}
