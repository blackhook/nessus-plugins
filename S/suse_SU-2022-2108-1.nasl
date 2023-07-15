##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2108-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(162378);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2021-22904", "CVE-2022-23633");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2108-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : rubygem-actionpack-5_1, rubygem-activesupport-5_1 (SUSE-SU-2022:2108-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:2108-1 advisory.

  - The actionpack ruby gem before 6.1.3.2, 6.0.3.7, 5.2.4.6, 5.2.6 suffers from a possible denial of service
    vulnerability in the Token Authentication logic in Action Controller due to a too permissive regular
    expression. Impacted code uses `authenticate_or_request_with_http_token` or `authenticate_with_http_token`
    for request authentication. (CVE-2021-22904)

  - Action Pack is a framework for handling and responding to web requests. Under certain circumstances
    response bodies will not be closed. In the event a response is *not* notified of a `close`,
    `ActionDispatch::Executor` will not know to reset thread local state for the next request. This can lead
    to data being leaked to subsequent requests.This has been fixed in Rails 7.0.2.1, 6.1.4.5, 6.0.4.5, and
    5.2.6.1. Upgrading is highly recommended, but to work around this problem a middleware described in GHSA-
    wh98-p28r-vrc9 can be used. (CVE-2022-23633)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196182");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-June/011300.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfd1218e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23633");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby2.5-rubygem-actionpack-5_1, ruby2.5-rubygem-actionpack-doc-5_1, ruby2.5-rubygem-
activesupport-5_1 and / or ruby2.5-rubygem-activesupport-doc-5_1 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23633");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-rubygem-actionpack-5_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-rubygem-activesupport-5_1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ruby2.5-rubygem-actionpack-5_1-5.1.4-150000.3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ruby2.5-rubygem-actionpack-doc-5_1-5.1.4-150000.3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ruby2.5-rubygem-activesupport-5_1-5.1.4-150000.3.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ruby2.5-rubygem-activesupport-doc-5_1-5.1.4-150000.3.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ruby2.5-rubygem-actionpack-5_1-5.1.4-150000.3.12.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-actionpack-doc-5_1-5.1.4-150000.3.12.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-activesupport-5_1-5.1.4-150000.3.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-activesupport-doc-5_1-5.1.4-150000.3.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-actionpack-5_1-5.1.4-150000.3.12.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15']},
    {'reference':'ruby2.5-rubygem-activesupport-5_1-5.1.4-150000.3.6.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15']},
    {'reference':'ruby2.5-rubygem-actionpack-5_1-5.1.4-150000.3.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'ruby2.5-rubygem-activesupport-5_1-5.1.4-150000.3.6.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'ruby2.5-rubygem-actionpack-5_1-5.1.4-150000.3.12.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'ruby2.5-rubygem-activesupport-5_1-5.1.4-150000.3.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'ruby2.5-rubygem-actionpack-5_1-5.1.4-150000.3.12.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ruby2.5-rubygem-activesupport-5_1-5.1.4-150000.3.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ruby2.5-rubygem-actionpack-5_1-5.1.4-150000.3.12.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'ruby2.5-rubygem-activesupport-5_1-5.1.4-150000.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby2.5-rubygem-actionpack-5_1 / ruby2.5-rubygem-actionpack-doc-5_1 / etc');
}
