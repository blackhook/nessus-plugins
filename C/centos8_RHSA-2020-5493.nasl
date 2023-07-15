##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:5493. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145933);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2020-24553",
    "CVE-2020-28362",
    "CVE-2020-28366",
    "CVE-2020-28367"
  );
  script_xref(name:"RHSA", value:"2020:5493");

  script_name(english:"CentOS 8 : go-toolset:rhel8 (CESA-2020:5493)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:5493 advisory.

  - golang: default Content-Type setting in net/http/cgi and net/http/fcgi could cause XSS (CVE-2020-24553)

  - golang: math/big: panic during recursive division of very large numbers (CVE-2020-28362)

  - golang: malicious symbol names can lead to code execution at build time (CVE-2020-28366)

  - golang: improper validation of cgo flags can lead to code execution at build time (CVE-2020-28367)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5493");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28367");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:delve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:go-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:golang-tests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/go-toolset');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:rhel8');
if ('rhel8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module go-toolset:' + module_ver);

var appstreams = {
    'go-toolset:rhel8': [
      {'reference':'delve-1.4.1-1.module_el8.3.0+471+76db7791', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'delve-1.4.1-1.module_el8.3.0+471+76db7791', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-docs-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-docs-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-misc-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-misc-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-race-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-race-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-src-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-src-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-tests-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-tests-1.14.12-1.module_el8.3.0+605+410c5674', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:rhel8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'delve / go-toolset / golang / golang-bin / golang-docs / golang-misc / etc');
}
