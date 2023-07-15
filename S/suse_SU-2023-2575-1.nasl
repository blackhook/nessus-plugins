#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2575-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177500);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id(
    "CVE-2020-7753",
    "CVE-2021-3807",
    "CVE-2021-3918",
    "CVE-2021-43138",
    "CVE-2022-0155",
    "CVE-2022-27664",
    "CVE-2022-31097",
    "CVE-2022-31107",
    "CVE-2022-32149",
    "CVE-2022-35957",
    "CVE-2022-36062",
    "CVE-2023-1387",
    "CVE-2023-1410"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2575-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : SUSE Manager Client Tools (SUSE-SU-2023:2575-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has a package installed that is affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:2575-1 advisory.

  - All versions of package trim are vulnerable to Regular Expression Denial of Service (ReDoS) via trim().
    (CVE-2020-7753)

  - ansi-regex is vulnerable to Inefficient Regular Expression Complexity (CVE-2021-3807)

  - json-schema is vulnerable to Improperly Controlled Modification of Object Prototype Attributes ('Prototype
    Pollution') (CVE-2021-3918)

  - In Async before 2.6.4 and 3.x before 3.2.2, a malicious user can obtain privileges via the mapValues()
    method, aka lib/internal/iterator.js createObjectIterator prototype pollution. (CVE-2021-43138)

  - follow-redirects is vulnerable to Exposure of Private Personal Information to an Unauthorized Actor
    (CVE-2022-0155)

  - In net/http in Go before 1.18.6 and 1.19.x before 1.19.1, attackers can cause a denial of service because
    an HTTP/2 connection can hang during closing if shutdown were preempted by a fatal error. (CVE-2022-27664)

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

  - An attacker may cause a denial of service by crafting an Accept-Language header which ParseAcceptLanguage
    will take significant time to parse. (CVE-2022-32149)

  - Grafana is an open-source platform for monitoring and observability. Versions prior to 9.1.6 and 8.5.13
    are vulnerable to an escalation from admin to server admin when auth proxy is used, allowing an admin to
    take over the server admin account and gain full control of the grafana instance. All installations should
    be upgraded as soon as possible. As a workaround deactivate auth proxy following the instructions at:
    https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/auth-
    proxy/ (CVE-2022-35957)

  - Grafana is an open-source platform for monitoring and observability. In versions prior to 8.5.13, 9.0.9,
    and 9.1.6, Grafana is subject to Improper Preservation of Permissions resulting in privilege escalation on
    some folders where Admin is the only used permission. The vulnerability impacts Grafana instances where
    RBAC was disabled and enabled afterwards, as the migrations which are translating legacy folder
    permissions to RBAC permissions do not account for the scenario where the only user permission in the
    folder is Admin, as a result RBAC adds permissions for Editors and Viewers which allow them to edit and
    view folders accordingly. This issue has been patched in versions 8.5.13, 9.0.9, and 9.1.6. A workaround
    when the impacted folder/dashboard is known is to remove the additional permissions manually.
    (CVE-2022-36062)

  - Grafana is an open-source platform for monitoring and observability. Starting with the 9.1 branch, Grafana
    introduced the ability to search for a JWT in the URL query parameter auth_token and use it as the
    authentication token. By enabling the url_login configuration option (disabled by default), a JWT might
    be sent to data sources. If an attacker has access to the data source, the leaked token could be used to
    authenticate to Grafana. (CVE-2023-1387)

  - Grafana is an open-source platform for monitoring and observability. Grafana had a stored XSS
    vulnerability in the Graphite FunctionDescription tooltip. The stored XSS vulnerability was possible due
    the value of the Function Description was not properly sanitized. An attacker needs to have control over
    the Graphite data source in order to manipulate a function description and a Grafana admin needs to
    configure the data source, later a Grafana user needs to select a tampered function and hover over the
    description. Users may upgrade to version 8.5.22, 9.2.15 and 9.3.11 to receive a fix. (CVE-2023-1410)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210907");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-June/029953.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-35957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1387");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1410");
  script_set_attribute(attribute:"solution", value:
"Update the affected grafana package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3918");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grafana");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'grafana-9.5.1-150200.3.41.3', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'grafana-9.5.1-150200.3.41.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'grafana-9.5.1-150200.3.41.3', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'grafana-9.5.1-150200.3.41.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'grafana-9.5.1-150200.3.41.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'grafana-9.5.1-150200.3.41.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grafana');
}
