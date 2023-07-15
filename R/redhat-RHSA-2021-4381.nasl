#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:4381. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155153);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2020-13558",
    "CVE-2020-24870",
    "CVE-2020-27918",
    "CVE-2020-29623",
    "CVE-2020-36241",
    "CVE-2021-1765",
    "CVE-2021-1788",
    "CVE-2021-1789",
    "CVE-2021-1799",
    "CVE-2021-1801",
    "CVE-2021-1844",
    "CVE-2021-1870",
    "CVE-2021-1871",
    "CVE-2021-21775",
    "CVE-2021-21779",
    "CVE-2021-21806",
    "CVE-2021-28650",
    "CVE-2021-30663",
    "CVE-2021-30665",
    "CVE-2021-30682",
    "CVE-2021-30689",
    "CVE-2021-30720",
    "CVE-2021-30734",
    "CVE-2021-30744",
    "CVE-2021-30749",
    "CVE-2021-30758",
    "CVE-2021-30795",
    "CVE-2021-30797",
    "CVE-2021-30799"
  );
  script_xref(name:"RHSA", value:"2021:4381");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");
  script_xref(name:"IAVA", value:"2021-A-0212-S");
  script_xref(name:"IAVA", value:"2021-A-0126-S");
  script_xref(name:"IAVA", value:"2021-A-0251-S");
  script_xref(name:"IAVA", value:"2021-A-0349-S");
  script_xref(name:"IAVA", value:"2021-A-0505-S");

  script_name(english:"RHEL 8 : GNOME (RHSA-2021:4381)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:4381 advisory.

  - webkitgtk: Use-after-free in AudioSourceProviderGStreamer leading to arbitrary code execution
    (CVE-2020-13558)

  - LibRaw: Stack buffer overflow in LibRaw::identify_process_dng_fields() in identify.cpp (CVE-2020-24870)

  - webkitgtk: Use-after-free leading to arbitrary code execution (CVE-2020-27918, CVE-2021-1788,
    CVE-2021-30795)

  - webkitgtk: User may be unable to fully delete browsing history (CVE-2020-29623)

  - CVE-2021-28650 gnome-autoar: Directory traversal via directory symbolic links pointing outside of the
    destination directory (incomplete  fix) (CVE-2020-36241)

  - webkitgtk: IFrame sandboxing policy violation (CVE-2021-1765, CVE-2021-1801)

  - webkitgtk: Type confusion issue leading to arbitrary code execution (CVE-2021-1789)

  - webkitgtk: Access to restricted ports on arbitrary servers via port redirection (CVE-2021-1799)

  - webkitgtk: Memory corruption issue leading to arbitrary code execution (CVE-2021-1844)

  - webkitgtk: Logic issue leading to arbitrary code execution (CVE-2021-1870, CVE-2021-1871)

  - webkitgtk: Use-after-free in ImageLoader dispatchPendingErrorEvent leading to information leak and
    possibly code execution (CVE-2021-21775)

  - webkitgtk: Use-after-free in WebCore::GraphicsContext leading to information leak and possibly code
    execution (CVE-2021-21779)

  - webkitgtk: Use-after-free in fireEventListeners leading to arbitrary code execution (CVE-2021-21806)

  - gnome-autoar: Directory traversal via directory symbolic links pointing outside of the destination
    directory (incomplete CVE-2020-36241 fix) (CVE-2021-28650)

  - webkitgtk: Integer overflow leading to arbitrary code execution (CVE-2021-30663)

  - webkitgtk: Memory corruption leading to arbitrary code execution (CVE-2021-30665)

  - webkitgtk: Logic issue leading to leak of sensitive user information (CVE-2021-30682)

  - webkitgtk: Logic issue leading to universal cross site scripting attack (CVE-2021-30689)

  - webkitgtk: Logic issue allowing access to restricted ports on arbitrary servers (CVE-2021-30720)

  - webkitgtk: Memory corruptions leading to arbitrary code execution (CVE-2021-30734, CVE-2021-30749,
    CVE-2021-30799)

  - webkitgtk: Cross-origin issue with iframe elements leading to universal cross site scripting attack
    (CVE-2021-30744)

  - webkitgtk: Type confusion leading to arbitrary code execution (CVE-2021-30758)

  - webkitgtk: Insufficient checks leading to arbitrary code execution (CVE-2021-30797)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-13558");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24870");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27918");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29623");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36241");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-1765");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-1788");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-1789");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-1799");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-1801");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-1844");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-1870");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-1871");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21775");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21779");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21806");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-28650");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30663");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30665");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30682");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30689");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30720");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30734");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30744");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30749");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30758");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30795");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30797");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30799");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1925640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1928794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1928886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1940026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1944867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1980441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986906");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30799");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 79, 119, 120, 190, 200, 416, 459, 843, 863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-autoar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'gnome-autoar-0.2.3-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-3.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-3.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-3.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-3.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-3.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-3.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-2.32.3-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-devel-2.32.3-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-2.32.3-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-devel-2.32.3-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      {'reference':'gnome-autoar-0.2.3-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-2.32.3-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-devel-2.32.3-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-2.32.3-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkit2gtk3-jsc-devel-2.32.3-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw / LibRaw-devel / gnome-autoar / webkit2gtk3 / webkit2gtk3-devel / etc');
}
