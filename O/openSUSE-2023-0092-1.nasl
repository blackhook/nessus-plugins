#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0092-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(174494);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id(
    "CVE-2023-1810",
    "CVE-2023-1811",
    "CVE-2023-1812",
    "CVE-2023-1813",
    "CVE-2023-1814",
    "CVE-2023-1815",
    "CVE-2023-1816",
    "CVE-2023-1817",
    "CVE-2023-1818",
    "CVE-2023-1819",
    "CVE-2023-1820",
    "CVE-2023-1821",
    "CVE-2023-1822",
    "CVE-2023-1823",
    "CVE-2023-2033"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/08");
  script_xref(name:"IAVA", value:"2023-A-0203-S");

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2023:0092-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0092-1 advisory.

  - Heap buffer overflow in Visuals in Google Chrome prior to 112.0.5615.49 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1810)

  - Use after free in Frames in Google Chrome prior to 112.0.5615.49 allowed a remote attacker who convinced a
    user to engage in specific UI interaction to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-1811)

  - Out of bounds memory access in DOM Bindings in Google Chrome prior to 112.0.5615.49 allowed a remote
    attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1812)

  - Inappropriate implementation in Extensions in Google Chrome prior to 112.0.5615.49 allowed an attacker who
    convinced a user to install a malicious extension to bypass file access restrictions via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-1813)

  - Insufficient validation of untrusted input in Safe Browsing in Google Chrome prior to 112.0.5615.49
    allowed a remote attacker to bypass download checking via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-1814)

  - Use after free in Networking APIs in Google Chrome prior to 112.0.5615.49 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-1815)

  - Incorrect security UI in Picture In Picture in Google Chrome prior to 112.0.5615.49 allowed a remote
    attacker to potentially perform navigation spoofing via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1816)

  - Insufficient policy enforcement in Intents in Google Chrome on Android prior to 112.0.5615.49 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1817)

  - Use after free in Vulkan in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-1818)

  - Out of bounds read in Accessibility in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1819)

  - Heap buffer overflow in Browser History in Google Chrome prior to 112.0.5615.49 allowed a remote attacker
    who convinced a user to engage in specific UI interaction to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-1820)

  - Inappropriate implementation in WebShare in Google Chrome prior to 112.0.5615.49 allowed a remote attacker
    to potentially hide the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-1821)

  - Incorrect security UI in Navigation in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to
    perform domain spoofing via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-1822)

  - Inappropriate implementation in FedCM in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to
    bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-1823)

  - Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-2033)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210478");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BRCY3MMGSLE74IM7LN5E42APXAOQ5ZQG/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4355860a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1820");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2033");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1818");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2033");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-112.0.5615.121-bp154.2.79.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-112.0.5615.121-bp154.2.79.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-112.0.5615.121-bp154.2.79.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-112.0.5615.121-bp154.2.79.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
