##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10086-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(164107);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-2603",
    "CVE-2022-2604",
    "CVE-2022-2605",
    "CVE-2022-2606",
    "CVE-2022-2607",
    "CVE-2022-2608",
    "CVE-2022-2609",
    "CVE-2022-2610",
    "CVE-2022-2611",
    "CVE-2022-2612",
    "CVE-2022-2613",
    "CVE-2022-2614",
    "CVE-2022-2615",
    "CVE-2022-2616",
    "CVE-2022-2617",
    "CVE-2022-2618",
    "CVE-2022-2619",
    "CVE-2022-2620",
    "CVE-2022-2621",
    "CVE-2022-2622",
    "CVE-2022-2623",
    "CVE-2022-2624"
  );

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2022:10086-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:10086-1 advisory.

  - Use after free in Omnibox in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2603)

  - Use after free in Safe Browsing in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2604)

  - Out of bounds read in Dawn in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2605)

  - Use after free in Managed devices API in Google Chrome prior to 104.0.5112.79 allowed a remote attacker
    who convinced a user to enable a specific Enterprise policy to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-2606)

  - Use after free in Tab Strip in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker
    who convinced a user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2607)

  - Use after free in Overview Mode in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote
    attacker who convinced a user to engage in specific user interactions to potentially exploit heap
    corruption via specific UI interactions. (CVE-2022-2608)

  - Use after free in Nearby Share in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote
    attacker who convinced a user to engage in specific user interactions to potentially exploit heap
    corruption via specific UI interactions. (CVE-2022-2609)

  - Insufficient policy enforcement in Background Fetch in Google Chrome prior to 104.0.5112.79 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-2610)

  - Inappropriate implementation in Fullscreen API in Google Chrome on Android prior to 104.0.5112.79 allowed
    a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-2611)

  - Side-channel information leakage in Keyboard input in Google Chrome prior to 104.0.5112.79 allowed a
    remote attacker who had compromised the renderer process to obtain potentially sensitive information from
    process memory via a crafted HTML page. (CVE-2022-2612)

  - Use after free in Input in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to enage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2613)

  - Use after free in Sign-In Flow in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2614)

  - Insufficient policy enforcement in Cookies in Google Chrome prior to 104.0.5112.79 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-2615)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 104.0.5112.79 allowed an attacker
    who convinced a user to install a malicious extension to spoof the contents of the Omnibox (URL bar) via a
    crafted Chrome Extension. (CVE-2022-2616)

  - Use after free in Extensions API in Google Chrome prior to 104.0.5112.79 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via specific UI
    interactions. (CVE-2022-2617)

  - Insufficient validation of untrusted input in Internals in Google Chrome prior to 104.0.5112.79 allowed a
    remote attacker to bypass download restrictions via a malicious file . (CVE-2022-2618)

  - Insufficient validation of untrusted input in Settings in Google Chrome prior to 104.0.5112.79 allowed an
    attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged
    page via a crafted HTML page. (CVE-2022-2619)

  - Use after free in WebUI in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2620)

  - Use after free in Extensions in Google Chrome prior to 104.0.5112.79 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific UI interactions.
    (CVE-2022-2621)

  - Insufficient validation of untrusted input in Safe Browsing in Google Chrome on Windows prior to
    104.0.5112.79 allowed a remote attacker to bypass download restrictions via a crafted file.
    (CVE-2022-2622)

  - Use after free in Offline in Google Chrome on Android prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2623)

  - Heap buffer overflow in PDF in Google Chrome prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via a
    crafted PDF file. (CVE-2022-2624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202075");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/43GPO54KYGHLDE7YCWHFLKD7CTXUXDWK/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6de430c2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2624");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2623");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
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
if (release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-104.0.5112.79-bp154.2.20.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-104.0.5112.79-bp154.2.20.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-104.0.5112.79-bp154.2.20.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-104.0.5112.79-bp154.2.20.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
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
