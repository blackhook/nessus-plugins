#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:14906-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159017);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2022-26381",
    "CVE-2022-26383",
    "CVE-2022-26384",
    "CVE-2022-26386",
    "CVE-2022-26387",
    "CVE-2022-26485",
    "CVE-2022-26486"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:14906-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/21");
  script_xref(name:"IAVA", value:"2022-A-0103-S");

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2022:14906-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:14906-1 advisory.

  - An attacker could have caused a use-after-free by forcing a text reflow in an SVG object leading to a
    potentially exploitable crash. This vulnerability affects Firefox < 98, Firefox ESR < 91.7, and
    Thunderbird < 91.7. (CVE-2022-26381)

  - When resizing a popup after requesting fullscreen access, the popup would not display the fullscreen
    notification. This vulnerability affects Firefox < 98, Firefox ESR < 91.7, and Thunderbird < 91.7.
    (CVE-2022-26383)

  - If an attacker could control the contents of an iframe sandboxed with <code>allow-popups</code> but not
    <code>allow-scripts</code>, they were able to craft a link that, when clicked, would lead to JavaScript
    execution in violation of the sandbox. This vulnerability affects Firefox < 98, Firefox ESR < 91.7, and
    Thunderbird < 91.7. (CVE-2022-26384)

  - Previously Firefox for macOS and Linux would download temporary files to a user-specific directory in
    <code>/tmp</code>, but this behavior was changed to download them to <code>/tmp</code> where they could be
    affected by other local users. This behavior was reverted to the original, user-specific directory.
    <br>*This bug only affects Firefox for macOS and Linux. Other operating systems are unaffected.*. This
    vulnerability affects Firefox ESR < 91.7 and Thunderbird < 91.7. (CVE-2022-26386)

  - When installing an add-on, Firefox verified the signature before prompting the user; but while the user
    was confirming the prompt, the underlying add-on file could have been modified and Firefox would not have
    noticed. This vulnerability affects Firefox < 98, Firefox ESR < 91.7, and Thunderbird < 91.7.
    (CVE-2022-26387)

  - Removing an XSLT parameter during processing could have lead to an exploitable use-after-free. We have had
    reports of attacks in the wild abusing this flaw. This vulnerability affects Firefox < 97.0.2, Firefox ESR
    < 91.6.1, Firefox for Android < 97.3.0, Thunderbird < 91.6.2, and Focus < 97.3.0. (CVE-2022-26485)

  - An unexpected message in the WebGPU IPC framework could lead to a use-after-free and exploitable sandbox
    escape. We have had reports of attacks in the wild abusing this flaw. This vulnerability affects Firefox <
    97.0.2, Firefox ESR < 91.6.1, Firefox for Android < 97.3.0, Thunderbird < 91.6.2, and Focus < 97.3.0.
    (CVE-2022-26486)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196900");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010417.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83e8d9ec");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26383");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26384");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26386");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26387");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26485");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26486");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-translations-common and / or MozillaFirefox-translations-other
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26486");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-91.7.0-78.167.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-11.4']},
    {'reference':'MozillaFirefox-translations-common-91.7.0-78.167.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-11.4']},
    {'reference':'MozillaFirefox-translations-other-91.7.0-78.167.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-11.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-translations-common / etc');
}
