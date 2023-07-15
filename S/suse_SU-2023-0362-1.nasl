#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0362-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(171401);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id(
    "CVE-2022-31123",
    "CVE-2022-31130",
    "CVE-2022-39201",
    "CVE-2022-39229",
    "CVE-2022-39306",
    "CVE-2022-39307"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0362-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : grafana (SUSE-SU-2023:0362-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has a package installed that is affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:0362-1 advisory.

  - Grafana is an open source observability and data visualization platform. Versions prior to 9.1.8 and
    8.5.14 are vulnerable to a bypass in the plugin signature verification. An attacker can convince a server
    admin to download and successfully run a malicious plugin even though unsigned plugins are not allowed.
    Versions 9.1.8 and 8.5.14 contain a patch for this issue. As a workaround, do not install plugins
    downloaded from untrusted sources. (CVE-2022-31123)

  - Grafana is an open source observability and data visualization platform. Versions of Grafana for endpoints
    prior to 9.1.8 and 8.5.14 could leak authentication tokens to some destination plugins under some
    conditions. The vulnerability impacts data source and plugin proxy endpoints with authentication tokens.
    The destination plugin could receive a user's Grafana authentication token. Versions 9.1.8 and 8.5.14
    contain a patch for this issue. As a workaround, do not use API keys, JWT authentication, or any HTTP
    Header based authentication. (CVE-2022-31130)

  - Grafana is an open source observability and data visualization platform. Starting with version 5.0.0-beta1
    and prior to versions 8.5.14 and 9.1.8, Grafana could leak the authentication cookie of users to plugins.
    The vulnerability impacts data source and plugin proxy endpoints under certain conditions. The destination
    plugin could receive a user's Grafana authentication cookie. Versions 9.1.8 and 8.5.14 contain a patch for
    this issue. There are no known workarounds. (CVE-2022-39201)

  - Grafana is an open source data visualization platform for metrics, logs, and traces. Versions prior to
    9.1.8 and 8.5.14 allow one user to block another user's login attempt by registering someone else'e email
    address as a username. A Grafana user's username and email address are unique fields, that means no other
    user can have the same username or email address as another user. A user can have an email address as a
    username. However, the login system allows users to log in with either username or email address. Since
    Grafana allows a user to log in with either their username or email address, this creates an usual
    behavior where `user_1` can register with one email address and `user_2` can register their username as
    `user_1`'s email address. This prevents `user_1` logging into the application since `user_1`'s password
    won't match with `user_2`'s email address. Versions 9.1.8 and 8.5.14 contain a patch. There are no
    workarounds for this issue. (CVE-2022-39229)

  - Grafana is an open-source platform for monitoring and observability. Versions prior to 9.2.4, or 8.5.15 on
    the 8.X branch, are subject to Improper Input Validation. Grafana admins can invite other members to the
    organization they are an admin for. When admins add members to the organization, non existing users get an
    email invite, existing members are added directly to the organization. When an invite link is sent, it
    allows users to sign up with whatever username/email address the user chooses and become a member of the
    organization. This introduces a vulnerability which can be used with malicious intent. This issue is
    patched in version 9.2.4, and has been backported to 8.5.15. There are no known workarounds.
    (CVE-2022-39306)

  - Grafana is an open-source platform for monitoring and observability. When using the forget password on the
    login page, a POST request is made to the `/api/user/password/sent-reset-email` URL. When the username or
    email does not exist, a JSON response contains a user not found message. This leaks information to
    unauthenticated users and introduces a security risk. This issue has been patched in 9.2.4 and backported
    to 8.5.15. There are no known workarounds. (CVE-2022-39307)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205227");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-February/013726.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ee72f12");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31123");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39306");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39307");
  script_set_attribute(attribute:"solution", value:
"Update the affected grafana package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/14");

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
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'grafana-8.5.15-150200.3.32.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'grafana-8.5.15-150200.3.32.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'grafana-8.5.15-150200.3.32.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
