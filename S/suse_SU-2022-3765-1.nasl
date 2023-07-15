#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3765-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(166603);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-21702",
    "CVE-2022-21703",
    "CVE-2022-21713",
    "CVE-2022-31097",
    "CVE-2022-31107"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3765-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : grafana (SUSE-SU-2022:3765-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has a package installed that is affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3765-1 advisory.

  - Grafana is an open-source platform for monitoring and observability. In affected versions an attacker
    could serve HTML content thru the Grafana datasource or plugin proxy and trick a user to visit this HTML
    page using a specially crafted link and execute a Cross-site Scripting (XSS) attack. The attacker could
    either compromise an existing datasource for a specific Grafana instance or either set up its own public
    service and instruct anyone to set it up in their Grafana instance. To be impacted, all of the following
    must be applicable. For the data source proxy: A Grafana HTTP-based datasource configured with Server as
    Access Mode and a URL set, the attacker has to be in control of the HTTP server serving the URL of above
    datasource, and a specially crafted link pointing at the attacker controlled data source must be clicked
    on by an authenticated user. For the plugin proxy: A Grafana HTTP-based app plugin configured and enabled
    with a URL set, the attacker has to be in control of the HTTP server serving the URL of above app, and a
    specially crafted link pointing at the attacker controlled plugin must be clocked on by an authenticated
    user. For the backend plugin resource: An attacker must be able to navigate an authenticated user to a
    compromised plugin through a crafted link. Users are advised to update to a patched version. There are no
    known workarounds for this vulnerability. (CVE-2022-21702)

  - Grafana is an open-source platform for monitoring and observability. Affected versions are subject to a
    cross site request forgery vulnerability which allows attackers to elevate their privileges by mounting
    cross-origin attacks against authenticated high-privilege Grafana users (for example, Editors or Admins).
    An attacker can exploit this vulnerability for privilege escalation by tricking an authenticated user into
    inviting the attacker as a new user with high privileges. Users are advised to upgrade as soon as
    possible. There are no known workarounds for this issue. (CVE-2022-21703)

  - Grafana is an open-source platform for monitoring and observability. Affected versions of Grafana expose
    multiple API endpoints which do not properly handle user authorization. `/teams/:teamId` will allow an
    authenticated attacker to view unintended data by querying for the specific team ID, `/teams/:search` will
    allow an authenticated attacker to search for teams and see the total number of available teams, including
    for those teams that the user does not have access to, and `/teams/:teamId/members` when editors_can_admin
    flag is enabled, an authenticated attacker can see unintended data by querying for the specific team ID.
    Users are advised to upgrade as soon as possible. There are no known workarounds for this issue.
    (CVE-2022-21713)

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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201539");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-October/012701.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9c9e234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31107");
  script_set_attribute(attribute:"solution", value:
"Update the affected grafana package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grafana");
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
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'grafana-8.3.10-150200.3.26.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'grafana-8.3.10-150200.3.26.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'grafana-8.3.10-150200.3.26.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'grafana-8.3.10-150200.3.26.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grafana');
}
