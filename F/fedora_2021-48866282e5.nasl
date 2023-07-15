##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-48866282e5
#

include('compat.inc');

if (description)
{
  script_id(145391);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-16044",
    "CVE-2021-21117",
    "CVE-2021-21118",
    "CVE-2021-21119",
    "CVE-2021-21120",
    "CVE-2021-21121",
    "CVE-2021-21122",
    "CVE-2021-21123",
    "CVE-2021-21124",
    "CVE-2021-21125",
    "CVE-2021-21126",
    "CVE-2021-21127",
    "CVE-2021-21128",
    "CVE-2021-21129",
    "CVE-2021-21130",
    "CVE-2021-21131",
    "CVE-2021-21132",
    "CVE-2021-21133",
    "CVE-2021-21134",
    "CVE-2021-21135",
    "CVE-2021-21136",
    "CVE-2021-21137",
    "CVE-2021-21138",
    "CVE-2021-21139",
    "CVE-2021-21140",
    "CVE-2021-21141"
  );
  script_xref(name:"FEDORA", value:"2021-48866282e5");

  script_name(english:"Fedora 33 : chromium (2021-48866282e5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 33 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2021-48866282e5 advisory.

  - Use after free in WebRTC in Google Chrome prior to 88.0.4324.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted SCTP packet. (CVE-2020-16044)

  - Insufficient policy enforcement in Cryptohome in Google Chrome prior to 88.0.4324.96 allowed a local
    attacker to perform OS-level privilege escalation via a crafted file. (CVE-2021-21117)

  - Insufficient data validation in V8 in Google Chrome prior to 88.0.4324.96 allowed a remote attacker to
    potentially perform out of bounds memory access via a crafted HTML page. (CVE-2021-21118)

  - Use after free in Media in Google Chrome prior to 88.0.4324.96 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-21119)

  - Use after free in WebSQL in Google Chrome prior to 88.0.4324.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-21120)

  - Use after free in Omnibox in Google Chrome on Linux prior to 88.0.4324.96 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2021-21121)

  - Use after free in Blink in Google Chrome prior to 88.0.4324.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-21122)

  - Insufficient data validation in File System API in Google Chrome prior to 88.0.4324.96 allowed a remote
    attacker to bypass filesystem restrictions via a crafted HTML page. (CVE-2021-21123)

  - Potential user after free in Speech Recognizer in Google Chrome on Android prior to 88.0.4324.96 allowed a
    remote attacker to potentially perform a sandbox escape via a crafted HTML page. (CVE-2021-21124)

  - Insufficient policy enforcement in File System API in Google Chrome on Windows prior to 88.0.4324.96
    allowed a remote attacker to bypass filesystem restrictions via a crafted HTML page. (CVE-2021-21125)

  - Insufficient policy enforcement in extensions in Google Chrome prior to 88.0.4324.96 allowed a remote
    attacker to bypass site isolation via a crafted Chrome Extension. (CVE-2021-21126)

  - Insufficient policy enforcement in extensions in Google Chrome prior to 88.0.4324.96 allowed a remote
    attacker to bypass content security policy via a crafted Chrome Extension. (CVE-2021-21127)

  - Heap buffer overflow in Blink in Google Chrome prior to 88.0.4324.96 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-21128)

  - Insufficient policy enforcement in File System API in Google Chrome prior to 88.0.4324.96 allowed a remote
    attacker to bypass filesystem restrictions via a crafted HTML page. (CVE-2021-21129, CVE-2021-21130,
    CVE-2021-21131)

  - Inappropriate implementation in DevTools in Google Chrome prior to 88.0.4324.96 allowed a remote attacker
    to potentially perform a sandbox escape via a crafted Chrome Extension. (CVE-2021-21132)

  - Insufficient policy enforcement in Downloads in Google Chrome prior to 88.0.4324.96 allowed an attacker
    who convinced a user to download files to bypass navigation restrictions via a crafted HTML page.
    (CVE-2021-21133)

  - Incorrect security UI in Page Info in Google Chrome on iOS prior to 88.0.4324.96 allowed a remote attacker
    to spoof security UI via a crafted HTML page. (CVE-2021-21134)

  - Inappropriate implementation in Performance API in Google Chrome prior to 88.0.4324.96 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-21135)

  - Insufficient policy enforcement in WebView in Google Chrome on Android prior to 88.0.4324.96 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-21136)

  - Inappropriate implementation in DevTools in Google Chrome prior to 88.0.4324.96 allowed a remote attacker
    to obtain potentially sensitive information from disk via a crafted HTML page. (CVE-2021-21137)

  - Use after free in DevTools in Google Chrome prior to 88.0.4324.96 allowed a local attacker to potentially
    perform a sandbox escape via a crafted file. (CVE-2021-21138)

  - Inappropriate implementation in iframe sandbox in Google Chrome prior to 88.0.4324.96 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2021-21139)

  - Uninitialized use in USB in Google Chrome prior to 88.0.4324.96 allowed a local attacker to potentially
    perform out of bounds memory access via via a USB device. (CVE-2021-21140)

  - Insufficient policy enforcement in File System API in Google Chrome prior to 88.0.4324.96 allowed a remote
    attacker to bypass file extension policy via a crafted HTML page. (CVE-2021-21141)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-48866282e5");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21117");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21132");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'chromium-88.0.4324.96-1.fc33', 'release':'FC33', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
