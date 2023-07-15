##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-4740239e28
#

include('compat.inc');

if (description)
{
  script_id(148782);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-21159",
    "CVE-2021-21160",
    "CVE-2021-21161",
    "CVE-2021-21162",
    "CVE-2021-21163",
    "CVE-2021-21164",
    "CVE-2021-21165",
    "CVE-2021-21166",
    "CVE-2021-21167",
    "CVE-2021-21168",
    "CVE-2021-21169",
    "CVE-2021-21170",
    "CVE-2021-21171",
    "CVE-2021-21172",
    "CVE-2021-21173",
    "CVE-2021-21174",
    "CVE-2021-21175",
    "CVE-2021-21176",
    "CVE-2021-21177",
    "CVE-2021-21178",
    "CVE-2021-21179",
    "CVE-2021-21180",
    "CVE-2021-21181",
    "CVE-2021-21182",
    "CVE-2021-21183",
    "CVE-2021-21184",
    "CVE-2021-21185",
    "CVE-2021-21186",
    "CVE-2021-21187",
    "CVE-2021-21188",
    "CVE-2021-21189",
    "CVE-2021-21190"
  );
  script_xref(name:"FEDORA", value:"2021-4740239e28");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Fedora 33 : chromium (2021-4740239e28)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 33 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2021-4740239e28 advisory.

  - Heap buffer overflow in TabStrip in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-21159, CVE-2021-21161)

  - Heap buffer overflow in WebAudio in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-21160)

  - Use after free in WebRTC in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-21162)

  - Insufficient data validation in Reader Mode in Google Chrome on iOS prior to 89.0.4389.72 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page and a malicious server. (CVE-2021-21163)

  - Insufficient data validation in Chrome on iOS in Google Chrome on iOS prior to 89.0.4389.72 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-21164)

  - Data race in audio in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to potentially exploit
    heap corruption via a crafted HTML page. (CVE-2021-21165, CVE-2021-21166)

  - Use after free in bookmarks in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-21167)

  - Insufficient policy enforcement in appcache in Google Chrome prior to 89.0.4389.72 allowed a remote
    attacker to obtain potentially sensitive information from process memory via a crafted HTML page.
    (CVE-2021-21168)

  - Out of bounds memory access in V8 in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to
    potentially perform out of bounds memory access via a crafted HTML page. (CVE-2021-21169)

  - Incorrect security UI in Loader in Google Chrome prior to 89.0.4389.72 allowed a remote attacker who had
    compromised the renderer process to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2021-21170)

  - Incorrect security UI in TabStrip and Navigation in Google Chrome on Android prior to 89.0.4389.72 allowed
    a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-21171)

  - Insufficient policy enforcement in File System API in Google Chrome on Windows prior to 89.0.4389.72
    allowed a remote attacker to bypass filesystem restrictions via a crafted HTML page. (CVE-2021-21172)

  - Side-channel information leakage in Network Internals in Google Chrome prior to 89.0.4389.72 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-21173)

  - Inappropriate implementation in Referrer in Google Chrome prior to 89.0.4389.72 allowed a remote attacker
    to bypass navigation restrictions via a crafted HTML page. (CVE-2021-21174)

  - Inappropriate implementation in Site isolation in Google Chrome prior to 89.0.4389.72 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-21175)

  - Inappropriate implementation in full screen mode in Google Chrome prior to 89.0.4389.72 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-21176)

  - Insufficient policy enforcement in Autofill in Google Chrome prior to 89.0.4389.72 allowed a remote
    attacker to obtain potentially sensitive information from process memory via a crafted HTML page.
    (CVE-2021-21177)

  - Inappropriate implementation in Compositing in Google Chrome on Linux and Windows prior to 89.0.4389.72
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2021-21178)

  - Use after free in Network Internals in Google Chrome on Linux prior to 89.0.4389.72 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-21179)

  - Use after free in tab search in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-21180)

  - Side-channel information leakage in autofill in Google Chrome prior to 89.0.4389.72 allowed a remote
    attacker to obtain potentially sensitive information from process memory via a crafted HTML page.
    (CVE-2021-21181)

  - Insufficient policy enforcement in navigations in Google Chrome prior to 89.0.4389.72 allowed a remote
    attacker who had compromised the renderer process to bypass navigation restrictions via a crafted HTML
    page. (CVE-2021-21182)

  - Inappropriate implementation in performance APIs in Google Chrome prior to 89.0.4389.72 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-21183, CVE-2021-21184)

  - Insufficient policy enforcement in extensions in Google Chrome prior to 89.0.4389.72 allowed an attacker
    who convinced a user to install a malicious extension to obtain sensitive information via a crafted Chrome
    Extension. (CVE-2021-21185)

  - Insufficient policy enforcement in QR scanning in Google Chrome on iOS prior to 89.0.4389.72 allowed an
    attacker who convinced the user to scan a QR code to bypass navigation restrictions via a crafted QR code.
    (CVE-2021-21186)

  - Insufficient data validation in URL formatting in Google Chrome prior to 89.0.4389.72 allowed a remote
    attacker to perform domain spoofing via IDN homographs via a crafted domain name. (CVE-2021-21187)

  - Use after free in Blink in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-21188)

  - Insufficient policy enforcement in payments in Google Chrome prior to 89.0.4389.72 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2021-21189)

  - Uninitialized data in PDFium in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted PDF file. (CVE-2021-21190)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-4740239e28");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21190");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Fedora' >!< release) audit(AUDIT_OS_NOT, 'Fedora');
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 33', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

pkgs = [
    {'reference':'chromium-89.0.4389.90-3.fc33', 'release':'FC33', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium');
}
