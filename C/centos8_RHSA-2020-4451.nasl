##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:4451. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145826);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2019-8625",
    "CVE-2019-8710",
    "CVE-2019-8720",
    "CVE-2019-8743",
    "CVE-2019-8764",
    "CVE-2019-8766",
    "CVE-2019-8769",
    "CVE-2019-8771",
    "CVE-2019-8782",
    "CVE-2019-8783",
    "CVE-2019-8808",
    "CVE-2019-8811",
    "CVE-2019-8812",
    "CVE-2019-8813",
    "CVE-2019-8814",
    "CVE-2019-8815",
    "CVE-2019-8816",
    "CVE-2019-8819",
    "CVE-2019-8820",
    "CVE-2019-8823",
    "CVE-2019-8835",
    "CVE-2019-8844",
    "CVE-2019-8846",
    "CVE-2020-3862",
    "CVE-2020-3864",
    "CVE-2020-3865",
    "CVE-2020-3867",
    "CVE-2020-3868",
    "CVE-2020-3885",
    "CVE-2020-3894",
    "CVE-2020-3895",
    "CVE-2020-3897",
    "CVE-2020-3899",
    "CVE-2020-3900",
    "CVE-2020-3901",
    "CVE-2020-3902",
    "CVE-2020-9802",
    "CVE-2020-9803",
    "CVE-2020-9805",
    "CVE-2020-9806",
    "CVE-2020-9807",
    "CVE-2020-9843",
    "CVE-2020-9850",
    "CVE-2020-9862",
    "CVE-2020-9893",
    "CVE-2020-9894",
    "CVE-2020-9895",
    "CVE-2020-9915",
    "CVE-2020-9925",
    "CVE-2020-10018",
    "CVE-2020-11793",
    "CVE-2020-14391",
    "CVE-2020-15503"
  );
  script_xref(name:"RHSA", value:"2020:4451");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"CentOS 8 : GNOME (CESA-2020:4451)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:4451 advisory.

  - webkitgtk: Incorrect state management leading to universal cross-site scripting (CVE-2019-8625,
    CVE-2019-8813, CVE-2020-3867)

  - webkitgtk: Multiple memory corruption issues leading to arbitrary code execution (CVE-2019-8710,
    CVE-2019-8720, CVE-2019-8766, CVE-2019-8782, CVE-2019-8783, CVE-2019-8808, CVE-2019-8811, CVE-2019-8812,
    CVE-2019-8814, CVE-2019-8815, CVE-2019-8816, CVE-2019-8819, CVE-2019-8820, CVE-2019-8823, CVE-2020-3868)

  - webkitgtk: Multiple memory corruption  issues leading to arbitrary code execution (CVE-2019-8743)

  - webkitgtk: Incorrect state  management leading to universal cross-site scripting (CVE-2019-8764)

  - webkitgtk: Websites could reveal browsing history (CVE-2019-8769)

  - webkitgtk: Violation of iframe sandboxing policy (CVE-2019-8771)

  - webkitgtk: Processing maliciously crafted web content may lead to arbitrary code execution (CVE-2019-8835,
    CVE-2019-8844)

  - webkitgtk: Use after free issue may lead to remote code execution (CVE-2019-8846)

  - webkitgtk: Use-after-free issue in accessibility/AXObjectCache.cpp (CVE-2020-10018)

  - webkitgtk: use-after-free via crafted web content (CVE-2020-11793)

  - gnome-settings-daemon: Red Hat Customer Portal password logged and passed as command line argument when
    user registers through GNOME control center (CVE-2020-14391)

  - LibRaw: lack of thumbnail size range check can lead to buffer overflow (CVE-2020-15503)

  - webkitgtk: Denial of service via incorrect memory handling (CVE-2020-3862)

  - webkitgtk: Non-unique security origin for DOM object contexts (CVE-2020-3864)

  - webkitgtk: Incorrect security check for a top-level DOM object context (CVE-2020-3865)

  - webkitgtk: Incorrect processing of file URLs (CVE-2020-3885)

  - webkitgtk: Race condition allows reading of restricted memory (CVE-2020-3894)

  - webkitgtk: Memory corruption triggered by a malicious web content (CVE-2020-3895)

  - webkitgtk: Type confusion leading to arbitrary code execution (CVE-2020-3897, CVE-2020-3901)

  - webkitgtk: Memory consumption issue leading to arbitrary code execution (CVE-2020-3899)

  - webkitgtk: Memory corruption  triggered by a malicious web content (CVE-2020-3900)

  - webkitgtk: Input validation issue leading to cross-site script attack (CVE-2020-3902)

  - webkitgtk: Logic issue may lead to arbitrary code execution (CVE-2020-9802, CVE-2020-9850)

  - webkitgtk: Memory corruption may lead to arbitrary code execution (CVE-2020-9803, CVE-2020-9806,
    CVE-2020-9807)

  - webkitgtk: Logic issue may lead to cross site scripting (CVE-2020-9805)

  - webkitgtk: Input validation issue may lead to cross site scripting (CVE-2020-9843)

  - webkitgtk: Command injection in web inspector (CVE-2020-9862)

  - webkitgtk: Use-after-free may lead to application termination or arbitrary code execution (CVE-2020-9893,
    CVE-2020-9895)

  - webkitgtk: Out-of-bounds read may lead to unexpected application termination or arbitrary code execution
    (CVE-2020-9894)

  - webkitgtk: Access issue in content security policy (CVE-2020-9915)

  - webkitgtk: A logic issue may lead to cross site scripting (CVE-2020-9925)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4451");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3899");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-9895");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari in Operator Side Effect Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-jsc-devel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'gnome-settings-daemon-3.32.0-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.28.4-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.28.4-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.28.4-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.28.4-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.28.4-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.28.4-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.28.4-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.28.4-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw / LibRaw-devel / gnome-settings-daemon / webkit2gtk3 / etc');
}
