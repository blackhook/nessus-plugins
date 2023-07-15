#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1350-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154079);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-37956",
    "CVE-2021-37957",
    "CVE-2021-37958",
    "CVE-2021-37959",
    "CVE-2021-37960",
    "CVE-2021-37961",
    "CVE-2021-37962",
    "CVE-2021-37963",
    "CVE-2021-37964",
    "CVE-2021-37965",
    "CVE-2021-37966",
    "CVE-2021-37967",
    "CVE-2021-37968",
    "CVE-2021-37969",
    "CVE-2021-37970",
    "CVE-2021-37971",
    "CVE-2021-37972",
    "CVE-2021-37973",
    "CVE-2021-37974",
    "CVE-2021-37975",
    "CVE-2021-37976",
    "CVE-2021-37977",
    "CVE-2021-37978",
    "CVE-2021-37979",
    "CVE-2021-37980"
  );
  script_xref(name:"IAVA", value:"2021-A-0438-S");
  script_xref(name:"IAVA", value:"2021-A-0448-S");
  script_xref(name:"IAVA", value:"2021-A-0449-S");
  script_xref(name:"IAVA", value:"2021-A-0459-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2021:1350-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1350-1 advisory.

  - Use after free in Offline use in Google Chrome on Android prior to 94.0.4606.54 allowed a remote attacker
    who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37956)

  - Use after free in WebGPU in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-37957)

  - Inappropriate implementation in Navigation in Google Chrome on Windows prior to 94.0.4606.54 allowed a
    remote attacker to inject scripts or HTML into a privileged page via a crafted HTML page. (CVE-2021-37958)

  - Use after free in Task Manager in Google Chrome prior to 94.0.4606.54 allowed an attacker who convinced a
    user to enage in a series of user gestures to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37959)

  - : Inappropriate implementation in Blink graphics. (CVE-2021-37960)

  - Use after free in Tab Strip in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37961)

  - Use after free in Performance Manager in Google Chrome prior to 94.0.4606.54 allowed a remote attacker who
    had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37962)

  - Side-channel information leakage in DevTools in Google Chrome prior to 94.0.4606.54 allowed a remote
    attacker to bypass site isolation via a crafted HTML page. (CVE-2021-37963)

  - Inappropriate implementation in ChromeOS Networking in Google Chrome on ChromeOS prior to 94.0.4606.54
    allowed an attacker with a rogue wireless access point to to potentially carryout a wifi impersonation
    attack via a crafted ONC file. (CVE-2021-37964)

  - Inappropriate implementation in Background Fetch API in Google Chrome prior to 94.0.4606.54 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-37965, CVE-2021-37968)

  - Inappropriate implementation in Compositing in Google Chrome on Android prior to 94.0.4606.54 allowed a
    remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-37966)

  - Inappropriate implementation in Background Fetch API in Google Chrome prior to 94.0.4606.54 allowed a
    remote attacker who had compromised the renderer process to leak cross-origin data via a crafted HTML
    page. (CVE-2021-37967)

  - Inappropriate implementation in Google Updater in Google Chrome on Windows prior to 94.0.4606.54 allowed a
    remote attacker to perform local privilege escalation via a crafted file. (CVE-2021-37969)

  - Use after free in File System API in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37970)

  - Incorrect security UI in Web Browser UI in Google Chrome prior to 94.0.4606.54 allowed a remote attacker
    to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-37971)

  - Out of bounds read in libjpeg-turbo in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37972)

  - Use after free in Portals in Google Chrome prior to 94.0.4606.61 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-37973)

  - Use after free in Safebrowsing in Google Chrome prior to 94.0.4606.71 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37974)

  - Use after free in V8 in Google Chrome prior to 94.0.4606.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-37975)

  - Inappropriate implementation in Memory in Google Chrome prior to 94.0.4606.71 allowed a remote attacker to
    obtain potentially sensitive information from process memory via a crafted HTML page. (CVE-2021-37976)

  - : Use after free in Garbage Collection. (CVE-2021-37977)

  - This CVE was assigned by Chrome. Microsoft Edge (Chromium-based) ingests Chromium, which addresses this
    vulnerability. Please see Google Chrome Releases for more information. (CVE-2021-37978)

  - : Heap buffer overflow in WebRTC. (CVE-2021-37979)

  - : Inappropriate implementation in Sandbox. (CVE-2021-37980)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191463");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FGCILKKE7TLKATFOFTDHZ573UHODPDOM/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba7d1788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37980");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37979");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-37973");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-94.0.4606.81-lp152.2.132.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-94.0.4606.81-lp152.2.132.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium');
}
