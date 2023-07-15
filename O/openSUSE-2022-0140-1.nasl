#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0140-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156937);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/29");

  script_cve_id("CVE-2021-39226", "CVE-2021-43813");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"openSUSE 15 Security Update : grafana (openSUSE-SU-2022:0140-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0140-1 advisory.

  - Grafana is an open source data visualization platform. In affected versions unauthenticated and
    authenticated users are able to view the snapshot with the lowest database key by accessing the literal
    paths: /dashboard/snapshot/:key, or /api/snapshots/:key. If the snapshot public_mode configuration
    setting is set to true (vs default of false), unauthenticated users are able to delete the snapshot with
    the lowest database key by accessing the literal path: /api/snapshots-delete/:deleteKey. Regardless of the
    snapshot public_mode setting, authenticated users are able to delete the snapshot with the lowest
    database key by accessing the literal paths: /api/snapshots/:key, or /api/snapshots-delete/:deleteKey. The
    combination of deletion and viewing enables a complete walk through all snapshot data while resulting in
    complete snapshot data loss. This issue has been resolved in versions 8.1.6 and 7.5.11. If for some reason
    you cannot upgrade you can use a reverse proxy or similar to block access to the literal paths:
    /api/snapshots/:key, /api/snapshots-delete/:deleteKey, /dashboard/snapshot/:key, and /api/snapshots/:key.
    They have no normal function and can be disabled without side effects. (CVE-2021-39226)

  - Grafana is an open-source platform for monitoring and observability. Grafana prior to versions 8.3.2 and
    7.5.12 contains a directory traversal vulnerability for fully lowercase or fully uppercase .md files. The
    vulnerability is limited in scope, and only allows access to files with the extension .md to authenticated
    users only. Grafana Cloud instances have not been affected by the vulnerability. Users should upgrade to
    patched versions 8.3.2 or 7.5.12. For users who cannot upgrade, running a reverse proxy in front of
    Grafana that normalizes the PATH of the request will mitigate the vulnerability. The proxy will have to
    also be able to handle url encoded paths. Alternatively, for fully lowercase or fully uppercase .md files,
    users can block /api/plugins/.*/markdown/.* without losing any functionality beyond inlined plugin help
    text. (CVE-2021-43813)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193688");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZUS4G6GRHNJN7AR53SGJABSHRZM3XMOY/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b1fd9b3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43813");
  script_set_attribute(attribute:"solution", value:
"Update the affected grafana package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grafana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'grafana-7.5.12-3.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
