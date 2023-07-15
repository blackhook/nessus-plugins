#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3747-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(166596);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2022-21698", "CVE-2022-31097", "CVE-2022-31107");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3747-1");

  script_name(english:"SUSE SLES12 Security Update : SUSE Manager Client Tools (SUSE-SU-2022:3747-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:3747-1 advisory.

  - client_golang is the instrumentation library for Go applications in Prometheus, and the promhttp package
    in client_golang provides tooling around HTTP servers and clients. In client_golang prior to version
    1.11.1, HTTP server is susceptible to a Denial of Service through unbounded cardinality, and potential
    memory exhaustion, when handling requests with non-standard HTTP methods. In order to be affected, an
    instrumented software must use any of `promhttp.InstrumentHandler*` middleware except `RequestsInFlight`;
    not filter any specific methods (e.g GET) before middleware; pass metric with `method` label name to our
    middleware; and not have any firewall/LB/proxy that filters away requests with unknown `method`.
    client_golang version 1.11.1 contains a patch for this issue. Several workarounds are available, including
    removing the `method` label name from counter/gauge used in the InstrumentHandler; turning off affected
    promhttp handlers; adding custom middleware before promhttp handler that will sanitize the request method
    given by Go http.Request; and using a reverse proxy or web application firewall, configured to only allow
    a limited set of methods. (CVE-2022-21698)

  - Grafana is an open-source platform for monitoring and observability. Versions on the 8.x and 9.x branch
    prior to 9.0.3, 8.5.9, 8.4.10, and 8.3.10 are vulnerable to stored cross-site scripting via the Unified
    Alerting feature of Grafana. An attacker can exploit this vulnerability to escalate privilege from editor
    to admin by tricking an authenticated admin to click on a link. Versions 9.0.3, 8.5.9, 8.4.10, and 8.3.10
    contain a patch. As a workaround, it is possible to disable alerting or use legacy alerting.
    (CVE-2022-31097)

  - Grafana is an open-source platform for monitoring and observability. In versions 5.3 until 9.0.3, 8.5.9,
    8.4.10, and 8.3.10, it is possible for a malicious user who has authorization to log into a Grafana
    instance via a configured OAuth IdP which provides a login name to take over the account of another user
    in that Grafana instance. This can occur when the malicious user is authorized to log in to Grafana via
    OAuth, the malicious user's external user id is not already associated with an account in Grafana, the
    malicious user's email address is not already associated with an account in Grafana, and the malicious
    user knows the Grafana username of the target user. If these conditions are met, the malicious user can
    set their username in the OAuth provider to that of the target user, then go through the OAuth flow to log
    in to Grafana. Due to the way that external and internal user accounts are linked together during login,
    if the conditions above are all met then the malicious user will be able to log in to the target user's
    Grafana account. Versions 9.0.3, 8.5.9, 8.4.10, and 8.3.10 contain a patch for this issue. As a
    workaround, concerned users can disable OAuth login to their Grafana instance, or ensure that all users
    authorized to log in via OAuth have a corresponding user account in Grafana linked to their email address.
    (CVE-2022-31107)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201539");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-October/012709.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48e00192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31107");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-github-prometheus-node_exporter package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21698");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-31097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-prometheus-node_exporter");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'golang-github-prometheus-node_exporter-1.3.0-1.21.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'golang-github-prometheus-node_exporter-1.3.0-1.21.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'golang-github-prometheus-node_exporter-1.3.0-1.21.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'golang-github-prometheus-node_exporter-1.3.0-1.21.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-prometheus-node_exporter');
}
