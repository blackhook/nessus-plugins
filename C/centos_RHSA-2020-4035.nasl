##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4035 and
# CentOS Errata and Security Advisory 2020:4035 respectively.
##

include('compat.inc');

if (description)
{
  script_id(143288);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2019-6237",
    "CVE-2019-6251",
    "CVE-2019-8506",
    "CVE-2019-8524",
    "CVE-2019-8535",
    "CVE-2019-8536",
    "CVE-2019-8544",
    "CVE-2019-8551",
    "CVE-2019-8558",
    "CVE-2019-8559",
    "CVE-2019-8563",
    "CVE-2019-8571",
    "CVE-2019-8583",
    "CVE-2019-8584",
    "CVE-2019-8586",
    "CVE-2019-8587",
    "CVE-2019-8594",
    "CVE-2019-8595",
    "CVE-2019-8596",
    "CVE-2019-8597",
    "CVE-2019-8601",
    "CVE-2019-8607",
    "CVE-2019-8608",
    "CVE-2019-8609",
    "CVE-2019-8610",
    "CVE-2019-8611",
    "CVE-2019-8615",
    "CVE-2019-8619",
    "CVE-2019-8622",
    "CVE-2019-8623",
    "CVE-2019-8625",
    "CVE-2019-8644",
    "CVE-2019-8649",
    "CVE-2019-8658",
    "CVE-2019-8666",
    "CVE-2019-8669",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8674",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8678",
    "CVE-2019-8679",
    "CVE-2019-8680",
    "CVE-2019-8681",
    "CVE-2019-8683",
    "CVE-2019-8684",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-8707",
    "CVE-2019-8710",
    "CVE-2019-8719",
    "CVE-2019-8720",
    "CVE-2019-8726",
    "CVE-2019-8733",
    "CVE-2019-8735",
    "CVE-2019-8743",
    "CVE-2019-8763",
    "CVE-2019-8764",
    "CVE-2019-8765",
    "CVE-2019-8766",
    "CVE-2019-8768",
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
    "CVE-2019-8821",
    "CVE-2019-8822",
    "CVE-2019-8823",
    "CVE-2019-8835",
    "CVE-2019-8844",
    "CVE-2019-8846",
    "CVE-2019-11070",
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
    "CVE-2020-10018",
    "CVE-2020-11793"
  );
  script_bugtraq_id(
    108497,
    108566,
    109328,
    109329
  );
  script_xref(name:"RHSA", value:"2020:4035");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"CentOS 7 : webkitgtk4 (CESA-2020:4035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:4035 advisory.

  - webkitgtk: HTTP proxy setting deanonymization information disclosure (CVE-2019-11070)

  - webkitgtk: Multiple memory corruption issues leading to arbitrary code execution (CVE-2019-6237,
    CVE-2019-8571, CVE-2019-8583, CVE-2019-8584, CVE-2019-8586, CVE-2019-8587, CVE-2019-8594, CVE-2019-8595,
    CVE-2019-8596, CVE-2019-8597, CVE-2019-8601, CVE-2019-8608, CVE-2019-8609, CVE-2019-8610, CVE-2019-8611,
    CVE-2019-8615, CVE-2019-8619, CVE-2019-8622, CVE-2019-8623, CVE-2019-8644, CVE-2019-8666, CVE-2019-8669,
    CVE-2019-8671, CVE-2019-8672, CVE-2019-8673, CVE-2019-8676, CVE-2019-8677, CVE-2019-8678, CVE-2019-8679,
    CVE-2019-8680, CVE-2019-8681, CVE-2019-8683, CVE-2019-8684, CVE-2019-8686, CVE-2019-8687, CVE-2019-8688,
    CVE-2019-8689, CVE-2019-8707, CVE-2019-8710, CVE-2019-8720, CVE-2019-8726, CVE-2019-8733, CVE-2019-8735,
    CVE-2019-8763, CVE-2019-8765, CVE-2019-8766, CVE-2019-8782, CVE-2019-8783, CVE-2019-8808, CVE-2019-8811,
    CVE-2019-8812, CVE-2019-8814, CVE-2019-8815, CVE-2019-8816, CVE-2019-8819, CVE-2019-8820, CVE-2019-8821,
    CVE-2019-8822, CVE-2019-8823, CVE-2020-3868)

  - webkitgtk: processing maliciously crafted web content lead to URI spoofing (CVE-2019-6251)

  - webkitgtk: malicous web content leads to arbitrary code execution (CVE-2019-8506)

  - webkitgtk: malicious web content leads to arbitrary code execution (CVE-2019-8524, CVE-2019-8559,
    CVE-2019-8563)

  - webkitgtk: malicious crafted web content leads to arbitrary code execution (CVE-2019-8535, CVE-2019-8536,
    CVE-2019-8558)

  - webkitgtk: malicious crafted web content leads to arbitrary we content (CVE-2019-8544)

  - webkitgtk: malicious web content leads to cross site scripting (CVE-2019-8551)

  - webkitgtk: Out-of-bounds read leading to memory disclosure (CVE-2019-8607)

  - webkitgtk: Incorrect state management leading to universal cross-site scripting (CVE-2019-8625,
    CVE-2019-8649, CVE-2019-8658, CVE-2019-8674, CVE-2019-8690, CVE-2019-8719, CVE-2019-8813, CVE-2020-3867)

  - webkitgtk: Multiple memory corruption  issues leading to arbitrary code execution (CVE-2019-8743)

  - webkitgtk: Incorrect state  management leading to universal cross-site scripting (CVE-2019-8764)

  - webkitgtk: Browsing history could not be deleted (CVE-2019-8768)

  - webkitgtk: Websites could reveal browsing history (CVE-2019-8769)

  - webkitgtk: Violation of iframe sandboxing policy (CVE-2019-8771)

  - webkitgtk: Processing maliciously crafted web content may lead to arbitrary code execution (CVE-2019-8835,
    CVE-2019-8844)

  - webkitgtk: Use after free issue may lead to remote code execution (CVE-2019-8846)

  - webkitgtk: Use-after-free issue in accessibility/AXObjectCache.cpp (CVE-2020-10018)

  - webkitgtk: use-after-free via crafted web content (CVE-2020-11793)

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-October/012864.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8032934");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/79.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/94.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/119.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/400.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3899");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10018");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 79, 94, 119, 200, 400, 416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkitgtk4-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'webkitgtk4-2.28.2-2.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'webkitgtk4-2.28.2-2.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'webkitgtk4-devel-2.28.2-2.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'webkitgtk4-devel-2.28.2-2.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'webkitgtk4-doc-2.28.2-2.el7', 'release':'CentOS-7'},
    {'reference':'webkitgtk4-jsc-2.28.2-2.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'webkitgtk4-jsc-2.28.2-2.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'webkitgtk4-jsc-devel-2.28.2-2.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'webkitgtk4-jsc-devel-2.28.2-2.el7', 'cpu':'x86_64', 'release':'CentOS-7'}
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
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
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
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +
    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkitgtk4 / webkitgtk4-devel / webkitgtk4-doc / etc');
}
