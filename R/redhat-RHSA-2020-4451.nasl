##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4451. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142418);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

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

  script_name(english:"RHEL 8 : GNOME (RHSA-2020:4451)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4451 advisory.

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

  - webkitgtk: input validation issue may lead to a cross site scripting (CVE-2020-9952)

  - webkitgtk: Buffer overflow leading to arbitrary code execution (CVE-2021-30666)

  - webkitgtk: Memory corruption leading to arbitrary code execution (CVE-2021-30761)

  - webkitgtk: Use-after-free leading to arbitrary code execution (CVE-2021-30762)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8625");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8710");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8720");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8743");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8764");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8766");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8769");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8771");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8782");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8783");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8808");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8811");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8812");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8813");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8814");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8815");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8816");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8819");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8820");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8823");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8835");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8844");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8846");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3862");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3864");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3865");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3867");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3868");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3885");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3894");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3895");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3897");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3899");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3900");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3901");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3902");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9802");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9803");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9805");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9806");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9807");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9843");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9850");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9862");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9893");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9894");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9895");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9915");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9925");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9952");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10018");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11793");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14391");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15503");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30761");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30762");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1811721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1829369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1853477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1873093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1901219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986898");
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
  script_cwe_id(20, 77, 79, 119, 120, 125, 284, 400, 416, 522, 841);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.4/x86_64/appstream/debug',
      'content/aus/rhel8/8.4/x86_64/appstream/os',
      'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.4/x86_64/baseos/debug',
      'content/aus/rhel8/8.4/x86_64/baseos/os',
      'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.4/ppc64le/appstream/os',
      'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.4/ppc64le/baseos/os',
      'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap/os',
      'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/appstream/debug',
      'content/e4s/rhel8/8.4/x86_64/appstream/os',
      'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/baseos/debug',
      'content/e4s/rhel8/8.4/x86_64/baseos/os',
      'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.4/x86_64/highavailability/os',
      'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap/debug',
      'content/e4s/rhel8/8.4/x86_64/sap/os',
      'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/appstream/debug',
      'content/eus/rhel8/8.4/ppc64le/appstream/os',
      'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/baseos/debug',
      'content/eus/rhel8/8.4/ppc64le/baseos/os',
      'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.4/ppc64le/highavailability/os',
      'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap/debug',
      'content/eus/rhel8/8.4/ppc64le/sap/os',
      'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.4/ppc64le/supplementary/os',
      'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/appstream/debug',
      'content/eus/rhel8/8.4/x86_64/appstream/os',
      'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/baseos/debug',
      'content/eus/rhel8/8.4/x86_64/baseos/os',
      'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/highavailability/debug',
      'content/eus/rhel8/8.4/x86_64/highavailability/os',
      'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap/debug',
      'content/eus/rhel8/8.4/x86_64/sap/os',
      'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/supplementary/debug',
      'content/eus/rhel8/8.4/x86_64/supplementary/os',
      'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/appstream/debug',
      'content/tus/rhel8/8.4/x86_64/appstream/os',
      'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/baseos/debug',
      'content/tus/rhel8/8.4/x86_64/baseos/os',
      'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/highavailability/debug',
      'content/tus/rhel8/8.4/x86_64/highavailability/os',
      'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/nfv/debug',
      'content/tus/rhel8/8.4/x86_64/nfv/os',
      'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/rt/debug',
      'content/tus/rhel8/8.4/x86_64/rt/os',
      'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'gnome-settings-daemon-3.32.0-11.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-2.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-2.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-2.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-2.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-2.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-2.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-2.28.4-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-devel-2.28.4-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-2.28.4-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-devel-2.28.4-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/appstream/debug',
      'content/aus/rhel8/8.6/x86_64/appstream/os',
      'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.6/ppc64le/appstream/os',
      'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.6/ppc64le/baseos/os',
      'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap/os',
      'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/appstream/debug',
      'content/e4s/rhel8/8.6/x86_64/appstream/os',
      'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.6/x86_64/highavailability/os',
      'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap/debug',
      'content/e4s/rhel8/8.6/x86_64/sap/os',
      'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/appstream/debug',
      'content/eus/rhel8/8.6/ppc64le/appstream/os',
      'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/baseos/debug',
      'content/eus/rhel8/8.6/ppc64le/baseos/os',
      'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.6/ppc64le/highavailability/os',
      'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap/debug',
      'content/eus/rhel8/8.6/ppc64le/sap/os',
      'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.6/ppc64le/supplementary/os',
      'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/appstream/debug',
      'content/eus/rhel8/8.6/x86_64/appstream/os',
      'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/highavailability/debug',
      'content/eus/rhel8/8.6/x86_64/highavailability/os',
      'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap/debug',
      'content/eus/rhel8/8.6/x86_64/sap/os',
      'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/supplementary/debug',
      'content/eus/rhel8/8.6/x86_64/supplementary/os',
      'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/appstream/debug',
      'content/tus/rhel8/8.6/x86_64/appstream/os',
      'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/highavailability/debug',
      'content/tus/rhel8/8.6/x86_64/highavailability/os',
      'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/rt/os',
      'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'gnome-settings-daemon-3.32.0-11.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-2.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-2.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-2.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-2.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-2.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-2.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-2.28.4-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-devel-2.28.4-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-2.28.4-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-devel-2.28.4-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/highavailability/debug',
      'content/dist/rhel8/8/ppc64le/highavailability/os',
      'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
      'content/dist/rhel8/8/ppc64le/sap-solutions/os',
      'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap/debug',
      'content/dist/rhel8/8/ppc64le/sap/os',
      'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/supplementary/debug',
      'content/dist/rhel8/8/ppc64le/supplementary/os',
      'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/highavailability/debug',
      'content/dist/rhel8/8/x86_64/highavailability/os',
      'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/x86_64/nfv/debug',
      'content/dist/rhel8/8/x86_64/nfv/os',
      'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/x86_64/rt/debug',
      'content/dist/rhel8/8/x86_64/rt/os',
      'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap-solutions/debug',
      'content/dist/rhel8/8/x86_64/sap-solutions/os',
      'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap/debug',
      'content/dist/rhel8/8/x86_64/sap/os',
      'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
      'content/dist/rhel8/8/x86_64/supplementary/debug',
      'content/dist/rhel8/8/x86_64/supplementary/os',
      'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'gnome-settings-daemon-3.32.0-11.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-2.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-2.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-2.28.4-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-devel-2.28.4-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-2.28.4-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-devel-2.28.4-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw / LibRaw-devel / gnome-settings-daemon / webkit2gtk3 / etc');
}
