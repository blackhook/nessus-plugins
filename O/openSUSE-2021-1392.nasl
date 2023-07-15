#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1392-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154513);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-37981",
    "CVE-2021-37982",
    "CVE-2021-37983",
    "CVE-2021-37984",
    "CVE-2021-37985",
    "CVE-2021-37986",
    "CVE-2021-37987",
    "CVE-2021-37988",
    "CVE-2021-37989",
    "CVE-2021-37990",
    "CVE-2021-37991",
    "CVE-2021-37992",
    "CVE-2021-37993",
    "CVE-2021-37994",
    "CVE-2021-37995",
    "CVE-2021-37996"
  );

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2021:1392-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1392-1 advisory.

  - : Heap buffer overflow in Skia. (CVE-2021-37981)

  - : Use after free in Incognito. (CVE-2021-37982)

  - : Use after free in Dev Tools. (CVE-2021-37983)

  - : Heap buffer overflow in PDFium. (CVE-2021-37984)

  - : Use after free in V8. (CVE-2021-37985)

  - : Heap buffer overflow in Settings. (CVE-2021-37986)

  - : Use after free in Network APIs. (CVE-2021-37987)

  - : Use after free in Profiles. (CVE-2021-37988)

  - : Inappropriate implementation in Blink. (CVE-2021-37989)

  - : Inappropriate implementation in WebView. (CVE-2021-37990)

  - : Race in V8. (CVE-2021-37991)

  - : Out of bounds read in WebAudio. (CVE-2021-37992)

  - : Use after free in PDF Accessibility. (CVE-2021-37993)

  - : Inappropriate implementation in iFrame Sandbox. (CVE-2021-37994)

  - : Inappropriate implementation in WebApp Installer. (CVE-2021-37995)

  - : Insufficient validation of untrusted input in Downloads. (CVE-2021-37996)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191844");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5PA4QP5O5NS7MLCPJRQA74564MFVWF24/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73a3f306");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37996");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37993");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-37981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-95.0.4638.54-bp153.2.37.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-95.0.4638.54-bp153.2.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-95.0.4638.54-bp153.2.37.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-95.0.4638.54-bp153.2.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
