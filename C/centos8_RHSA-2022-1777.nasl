##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2022:1777. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160908);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-30809",
    "CVE-2021-30818",
    "CVE-2021-30823",
    "CVE-2021-30836",
    "CVE-2021-30846",
    "CVE-2021-30848",
    "CVE-2021-30849",
    "CVE-2021-30851",
    "CVE-2021-30884",
    "CVE-2021-30887",
    "CVE-2021-30888",
    "CVE-2021-30889",
    "CVE-2021-30890",
    "CVE-2021-30897",
    "CVE-2021-30934",
    "CVE-2021-30936",
    "CVE-2021-30951",
    "CVE-2021-30952",
    "CVE-2021-30953",
    "CVE-2021-30954",
    "CVE-2021-30984",
    "CVE-2021-45481",
    "CVE-2021-45482",
    "CVE-2021-45483",
    "CVE-2022-22589",
    "CVE-2022-22590",
    "CVE-2022-22592",
    "CVE-2022-22594",
    "CVE-2022-22620",
    "CVE-2022-22637"
  );
  script_xref(name:"RHSA", value:"2022:1777");
  script_xref(name:"IAVA", value:"2021-A-0505-S");
  script_xref(name:"IAVA", value:"2021-A-0577-S");
  script_xref(name:"IAVA", value:"2022-A-0051-S");
  script_xref(name:"IAVA", value:"2022-A-0118-S");
  script_xref(name:"IAVA", value:"2022-A-0082-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/25");

  script_name(english:"CentOS 8 : webkit2gtk3 (CESA-2022:1777)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2022:1777 advisory.

  - webkitgtk: Use-after-free leading to arbitrary code execution (CVE-2021-30809)

  - webkitgtk: Type confusion issue leading to arbitrary code execution (CVE-2021-30818)

  - webkitgtk: Logic issue leading to HSTS bypass (CVE-2021-30823)

  - webkitgtk: Out-of-bounds read leading to memory disclosure (CVE-2021-30836)

  - webkitgtk: Memory corruption issue leading to arbitrary code execution (CVE-2021-30846, CVE-2021-30848,
    CVE-2021-30851)

  - webkitgtk: Multiple memory corruption issue leading to arbitrary code execution (CVE-2021-30849)

  - webkitgtk: CSS compositing issue leading to revealing of the browsing history (CVE-2021-30884)

  - webkitgtk: Logic issue leading to Content Security Policy bypass (CVE-2021-30887)

  - webkitgtk: Information leak via Content Security Policy reports (CVE-2021-30888)

  - webkitgtk: Buffer overflow leading to arbitrary code execution (CVE-2021-30889)

  - webkitgtk: Logic issue leading to universal cross-site scripting (CVE-2021-30890)

  - webkitgtk: Cross-origin data exfiltration via resource timing API (CVE-2021-30897)

  - webkitgtk: Processing maliciously crafted web content may lead to arbitrary code execution
    (CVE-2021-30934, CVE-2021-30936, CVE-2021-30951, CVE-2021-30952, CVE-2021-30953, CVE-2021-30954,
    CVE-2021-30984, CVE-2022-22590)

  - webkitgtk: Incorrect memory allocation in WebCore::ImageBufferCairoImageSurfaceBackend::create
    (CVE-2021-45481)

  - webkitgtk: use-after-free in WebCore::ContainerNode::firstChild (CVE-2021-45482)

  - webkitgtk: use-after-free in WebCore::Frame::page (CVE-2021-45483)

  - webkitgtk: Processing a maliciously crafted mail message may lead to running arbitrary javascript
    (CVE-2022-22589)

  - webkitgtk: Processing maliciously crafted web content may prevent Content Security Policy from being
    enforced (CVE-2022-22592)

  - webkitgtk: A malicious website may exfiltrate data cross-origin (CVE-2022-22594)

  - webkitgtk: maliciously crafted web content may lead to arbitrary code execution due to use after free
    (CVE-2022-22620)

  - webkitgtk: logic issue was addressed with improved state management (CVE-2022-22637)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1777");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30954");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-22637");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
var os_ver = os_ver[1];
if ('CentOS Stream' >!< release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'webkit2gtk3-2.34.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.34.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.34.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.34.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.34.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.34.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.34.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.34.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkit2gtk3 / webkit2gtk3-devel / webkit2gtk3-jsc / etc');
}
