#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0821-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(173225);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2022-23552",
    "CVE-2022-39324",
    "CVE-2022-41723",
    "CVE-2022-46146"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0821-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : grafana (SUSE-SU-2023:0821-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has a package installed that is affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:0821-1 advisory.

  - Grafana is an open-source platform for monitoring and observability. Starting with the 8.1 branch and
    prior to versions 8.5.16, 9.2.10, and 9.3.4, Grafana had a stored XSS vulnerability affecting the core
    plugin GeoMap. The stored XSS vulnerability was possible because SVG files weren't properly sanitized and
    allowed arbitrary JavaScript to be executed in the context of the currently authorized user of the Grafana
    instance. An attacker needs to have the Editor role in order to change a panel to include either an
    external URL to a SVG-file containing JavaScript, or use the `data:` scheme to load an inline SVG-file
    containing JavaScript. This means that vertical privilege escalation is possible, where a user with Editor
    role can change to a known password for a user having Admin role if the user with Admin role executes
    malicious JavaScript viewing a dashboard. Users may upgrade to version 8.5.16, 9.2.10, or 9.3.4 to receive
    a fix. (CVE-2022-23552)

  - Grafana is an open-source platform for monitoring and observability. Prior to versions 8.5.16 and 9.2.8,
    malicious user can create a snapshot and arbitrarily choose the `originalUrl` parameter by editing the
    query, thanks to a web proxy. When another user opens the URL of the snapshot, they will be presented with
    the regular web interface delivered by the trusted Grafana server. The `Open original dashboard` button no
    longer points to the to the real original dashboard but to the attacker's injected URL. This issue is
    fixed in versions 8.5.16 and 9.2.8. (CVE-2022-39324)

  - A maliciously crafted HTTP/2 stream could cause excessive CPU consumption in the HPACK decoder, sufficient
    to cause a denial of service from a small number of small requests. (CVE-2022-41723)

  - Prometheus Exporter Toolkit is a utility package to build exporters. Prior to versions 0.7.2 and 0.8.2, if
    someone has access to a Prometheus web.yml file and users' bcrypted passwords, they can bypass security by
    poisoning the built-in authentication cache. Versions 0.7.2 and 0.8.2 contain a fix for the issue. There
    is no workaround, but attacker must have access to the hashed password to use this functionality.
    (CVE-2022-46146)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208293");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-March/014097.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4355854b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39324");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46146");
  script_set_attribute(attribute:"solution", value:
"Update the affected grafana package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46146");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

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
    {'reference':'grafana-8.5.20-150200.3.35.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'grafana-8.5.20-150200.3.35.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'grafana-8.5.20-150200.3.35.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
