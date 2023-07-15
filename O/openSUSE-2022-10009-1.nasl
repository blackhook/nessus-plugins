##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10009-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(162322);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-1853",
    "CVE-2022-1854",
    "CVE-2022-1855",
    "CVE-2022-1856",
    "CVE-2022-1857",
    "CVE-2022-1858",
    "CVE-2022-1859",
    "CVE-2022-1860",
    "CVE-2022-1861",
    "CVE-2022-1862",
    "CVE-2022-1863",
    "CVE-2022-1864",
    "CVE-2022-1865",
    "CVE-2022-1866",
    "CVE-2022-1867",
    "CVE-2022-1868",
    "CVE-2022-1869",
    "CVE-2022-1870",
    "CVE-2022-1871",
    "CVE-2022-1872",
    "CVE-2022-1873",
    "CVE-2022-1874",
    "CVE-2022-1875",
    "CVE-2022-1876",
    "CVE-2022-2007",
    "CVE-2022-2008",
    "CVE-2022-2010",
    "CVE-2022-2011"
  );
  script_xref(name:"IAVA", value:"2022-A-0231-S");

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2022:10009-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:10009-1 advisory.

  - Use after free in Indexed DB. (CVE-2022-1853)

  - Use after free in ANGLE. (CVE-2022-1854, CVE-2022-2011)

  - Use after free in Messaging. (CVE-2022-1855)

  - Use after free in User Education. (CVE-2022-1856)

  - Insufficient policy enforcement in File System API. (CVE-2022-1857, CVE-2022-1871)

  - Out of bounds read in DevTools. (CVE-2022-1858)

  - Use after free in Performance Manager. (CVE-2022-1859)

  - Use after free in UI Foundations. (CVE-2022-1860)

  - Use after free in Sharing. (CVE-2022-1861)

  - Inappropriate implementation in Extensions. (CVE-2022-1862)

  - Use after free in Tab Groups. (CVE-2022-1863)

  - Use after free in WebApp Installs. (CVE-2022-1864)

  - Use after free in Bookmarks. (CVE-2022-1865)

  - Use after free in Tablet Mode. (CVE-2022-1866)

  - Insufficient validation of untrusted input in Data Transfer. (CVE-2022-1867)

  - Inappropriate implementation in Extensions API. (CVE-2022-1868)

  - Type Confusion in V8. (CVE-2022-1869)

  - Use after free in App Service. (CVE-2022-1870)

  - Insufficient policy enforcement in Extensions API. (CVE-2022-1872)

  - Insufficient policy enforcement in COOP. (CVE-2022-1873)

  - Insufficient policy enforcement in Safe Browsing. (CVE-2022-1874)

  - Inappropriate implementation in PDF. (CVE-2022-1875)

  - Heap buffer overflow in DevTools. (CVE-2022-1876)

  - Use after free in WebGPU. (CVE-2022-2007)

  - Out of bounds memory access in WebGL. (CVE-2022-2008)

  - Out of bounds read in compositing. (CVE-2022-2010)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200423");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RUXRSXC3TACZ74MCVMECNI7P2X6JM2NF/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea5b2420");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2011");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2011");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1853");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'chromedriver-102.0.5005.115-bp153.2.101.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-102.0.5005.115-bp153.2.101.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-102.0.5005.115-bp153.2.101.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-102.0.5005.115-bp153.2.101.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium');
}
