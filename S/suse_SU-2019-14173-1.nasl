#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2019:14173-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150554);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2019-9812",
    "CVE-2019-11740",
    "CVE-2019-11742",
    "CVE-2019-11743",
    "CVE-2019-11744",
    "CVE-2019-11746",
    "CVE-2019-11752",
    "CVE-2019-11753"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2019:14173-1");
  script_xref(name:"IAVA", value:"2019-A-0342-S");
  script_xref(name:"IAVA", value:"2019-A-0324-S");

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox, firefox-glib2, firefox-gtk3 (SUSE-SU-2019:14173-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2019:14173-1 advisory.

  - Mozilla developers and community members reported memory safety bugs present in Firefox 68, Firefox ESR
    68, and Firefox 60.8. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects
    Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1.
    (CVE-2019-11740)

  - A same-origin policy violation occurs allowing the theft of cross-origin images through a combination of
    SVG filters and a <canvas> element due to an error in how same-origin policy is applied to cached
    image content. The resulting same-origin policy violation could allow for data theft. This vulnerability
    affects Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1.
    (CVE-2019-11742)

  - Navigation events were not fully adhering to the W3C's Navigation-Timing Level 2 draft specification in
    some instances for the unload event, which restricts access to detailed timing attributes to only be same-
    origin. This resulted in potential cross-origin information exposure of history through timing side-
    channel attacks. This vulnerability affects Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox
    ESR < 60.9, and Firefox ESR < 68.1. (CVE-2019-11743)

  - Some HTML elements, such as <title> and <textarea>, can contain literal angle brackets without
    treating them as markup. It is possible to pass a literal closing tag to .innerHTML on these elements, and
    subsequent content after that will be parsed as if it were outside the tag. This can lead to XSS if a site
    does not filter user input as strictly for these elements as it does for other elements. This
    vulnerability affects Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and
    Firefox ESR < 68.1. (CVE-2019-11744)

  - A use-after-free vulnerability can occur while manipulating video elements if the body is freed while
    still in use. This results in a potentially exploitable crash. This vulnerability affects Firefox < 69,
    Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1. (CVE-2019-11746)

  - It is possible to delete an IndexedDB key value and subsequently try to extract it during conversion. This
    results in a use-after-free and a potentially exploitable crash. This vulnerability affects Firefox < 69,
    Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1. (CVE-2019-11752)

  - The Firefox installer allows Firefox to be installed to a custom user writable location, leaving it
    unprotected from manipulation by unprivileged users or malware. If the Mozilla Maintenance Service is
    manipulated to update this unprotected location and the updated maintenance service in the unprotected
    location has been altered, the altered maintenance service can run with elevated privileges during the
    update process due to a lack of integrity checks. This allows for privilege escalation if the executable
    has been replaced locally. *Note: This attack requires local system access and only affects Windows.
    Other operating systems are not affected.*. This vulnerability affects Firefox < 69, Firefox ESR < 60.9,
    and Firefox ESR < 68.1. (CVE-2019-11753)

  - Given a compromised sandboxed content process due to a separate vulnerability, it is possible to escape
    that sandbox by loading accounts.firefox.com in that process and forcing a log-in to a malicious Firefox
    Sync account. Preference settings that disable the sandbox are then synchronized to the local machine and
    the compromised browser would restart without the sandbox if a crash is triggered. This vulnerability
    affects Firefox ESR < 60.9, Firefox ESR < 68.1, and Firefox < 69. (CVE-2019-9812)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1145550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149303");
  # https://lists.suse.com/pipermail/sle-security-updates/2019-September/005928.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acc82874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9812");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-9812");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gio-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-glib2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-glib2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-amharic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-inuktitut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-multipress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-thai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-vietnamese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodules-tigrigna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libgtk-3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-gio-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-glib-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-gmodule-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-gobject-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-gthread-2_0-0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
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
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'MozillaFirefox-60.9.0esr-78.46', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-60.9.0esr-78.46', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-60.9.0esr-78.46', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gio-branding-upstream-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-glib2-lang-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-glib2-tools-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-branding-upstream-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-data-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-amharic-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-inuktitut-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-multipress-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-thai-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-vietnamese-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-xim-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodules-tigrigna-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-lang-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-tools-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libgtk-3-0-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-gio-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-glib-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-gmodule-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-gobject-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-gthread-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-60.9.0esr-78.46', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-60.9.0esr-78.46', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-60.9.0esr-78.46', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gio-branding-upstream-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-glib2-lang-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-glib2-tools-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-branding-upstream-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-data-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-amharic-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-inuktitut-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-multipress-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-thai-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-vietnamese-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-xim-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodules-tigrigna-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-lang-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-tools-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libgtk-3-0-3.10.9-2.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-gio-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-glib-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-gmodule-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-gobject-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-gthread-2_0-0-2.54.3-2.11', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-translations-common / etc');
}
