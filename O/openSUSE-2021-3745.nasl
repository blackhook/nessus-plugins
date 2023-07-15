#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3745-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155656);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/17");

  script_cve_id(
    "CVE-2021-38503",
    "CVE-2021-38504",
    "CVE-2021-38505",
    "CVE-2021-38506",
    "CVE-2021-38507",
    "CVE-2021-38508",
    "CVE-2021-38509",
    "CVE-2021-38510"
  );
  script_xref(name:"IAVA", value:"2021-A-0527-S");

  script_name(english:"openSUSE 15 Security Update : MozillaFirefox (openSUSE-SU-2021:3745-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3745-1 advisory.

  - The iframe sandbox rules were not correctly applied to XSLT stylesheets, allowing an iframe to bypass
    restrictions such as executing scripts or navigating the top-level frame.  (CVE-2021-38503)

  - When interacting with an HTML input element's file picker dialog with <code>webkitdirectory</code> set, a
    use-after-free could have resulted, leading to memory corruption and a potentially exploitable crash.
    (CVE-2021-38504)

  - Microsoft introduced a new feature in Windows 10 known as Cloud Clipboard which, if enabled, will record
    data copied to the clipboard to the cloud, and make it available on other computers in certain scenarios.
    Applications that wish to prevent copied data from being recorded in Cloud History must use specific
    clipboard formats; and Firefox before versions 94 and ESR 91.3 did not implement them. This could have
    caused sensitive data to be recorded to a user's Microsoft account. This bug only affects Firefox for
    Windows 10+ with Cloud Clipboard enabled. Other operating systems are unaffected.  (CVE-2021-38505)

  - Through a series of navigations, Firefox could have entered fullscreen mode without notification or
    warning to the user. This could lead to spoofing attacks on the browser UI including phishing.
    (CVE-2021-38506)

  - Mozilla: Opportunistic Encryption in HTTP2 could be used to bypass the Same-Origin-Policy on services
    hosted on other ports (CVE-2021-38507)

  - By displaying a form validity message in the correct location at the same time as a permission prompt
    (such as for geolocation), the validity message could have obscured the prompt, resulting in the user
    potentially being tricked into granting the permission.  (CVE-2021-38508)

  - Mozilla: Javascript alert box could have been spoofed onto an arbitrary domain (CVE-2021-38509)

  - The executable file warning was not presented when downloading .inetloc files, which can run commands on a
    user's computer. Note: This issue only affected Mac OS operating systems. Other operating systems are
    unaffected.  (CVE-2021-38510)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192250");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HANTLKSTN557DZ2MTOXFS2TQFKRJMZNC/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eafb3ebc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38510");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'MozillaFirefox-91.3.0-152.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaFirefox-branding-upstream-91.3.0-152.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaFirefox-devel-91.3.0-152.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaFirefox-translations-common-91.3.0-152.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaFirefox-translations-other-91.3.0-152.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-branding-upstream / etc');
}
