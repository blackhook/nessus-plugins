#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0763-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(172645);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id(
    "CVE-2023-25748",
    "CVE-2023-25749",
    "CVE-2023-25750",
    "CVE-2023-25751",
    "CVE-2023-25752",
    "CVE-2023-28159",
    "CVE-2023-28160",
    "CVE-2023-28161",
    "CVE-2023-28162",
    "CVE-2023-28163",
    "CVE-2023-28164",
    "CVE-2023-28176",
    "CVE-2023-28177"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0763-1");
  script_xref(name:"IAVA", value:"2023-A-0132-S");

  script_name(english:"SUSE SLES12 Security Update : MozillaFirefox (SUSE-SU-2023:0763-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2023:0763-1 advisory.

  - By displaying a prompt with a long description, the fullscreen notification could have been hidden,
    resulting in potential user confusion or spoofing attacks.  This bug only affects Firefox for Android.
    Other operating systems are unaffected.  (CVE-2023-25748)

  - Android applications with unpatched vulnerabilities can be launched from a browser using Intents, exposing
    users to these vulnerabilities. Firefox will now confirm with users that they want to launch an external
    application before doing so.  This bug only affects Firefox for Android. Other versions of Firefox are
    unaffected.  (CVE-2023-25749)

  - Under certain circumstances, a ServiceWorker's offline cache may have leaked to the file system when using
    private browsing mode.  (CVE-2023-25750)

  - Sometimes, when invalidating JIT code while following an iterator, the newly generated code could be
    overwritten incorrectly. This could lead to a potentially exploitable crash.  (CVE-2023-25751)

  - When accessing throttled streams, the count of available bytes needed to be checked in the calling
    function to be within bounds. This may have lead future code to be incorrect and vulnerable.
    (CVE-2023-25752)

  - The fullscreen notification could have been hidden on Firefox for Android by using download popups,
    resulting in potential user confusion or spoofing attacks.  This bug only affects Firefox for Android.
    Other operating systems are unaffected.  (CVE-2023-28159)

  - When following a redirect to a publicly accessible web extension file, the URL may have been translated to
    the actual local path, leaking potentially sensitive information.  (CVE-2023-28160)

  - If temporary one-time permissions, such as the ability to use the Camera, were granted to a document
    loaded using a file: URL, that permission persisted in that tab for all other documents loaded from a
    file: URL. This is potentially dangerous if the local files came from different sources, such as in a
    download directory.  (CVE-2023-28161)

  - While implementing AudioWorklets, some code may have casted one type to another, invalid, dynamic type.
    This could have led to a potentially exploitable crash.  (CVE-2023-28162)

  - When downloading files through the Save As dialog on Windows with suggested filenames containing
    environment variable names, Windows would have resolved those in the context of the current user.  This
    bug only affects Firefox on Windows. Other versions of Firefox are unaffected.  (CVE-2023-28163)

  - Dragging a URL from a cross-origin iframe that was removed during the drag could have led to user
    confusion and website spoofing attacks.  (CVE-2023-28164)

  - Mozilla developers Timothy Nikkel, Andrew McCreight, and the Mozilla Fuzzing Team reported memory safety
    bugs present in Thunderbird 102.8. Some of these bugs showed evidence of memory corruption and we presume
    that with enough effort some of these could have been exploited to run arbitrary code.  (CVE-2023-28176)

  - Mozilla developers and community members Calixte Denizet, Gabriele Svelto, Andrew McCreight, and the
    Mozilla Fuzzing Team reported memory safety bugs present in Firefox 110. Some of these bugs showed
    evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code.  (CVE-2023-28177)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209173");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-March/014065.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d91a5a43");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28163");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28164");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28177");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-devel and / or MozillaFirefox-translations-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-102.9.0-112.153.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.4', 'sles-release-4']},
    {'reference':'MozillaFirefox-devel-102.9.0-112.153.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.4', 'sles-release-4']},
    {'reference':'MozillaFirefox-translations-common-102.9.0-112.153.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.4', 'sles-release-4']},
    {'reference':'MozillaFirefox-102.9.0-112.153.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'MozillaFirefox-devel-102.9.0-112.153.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'MozillaFirefox-translations-common-102.9.0-112.153.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'MozillaFirefox-102.9.0-112.153.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'MozillaFirefox-devel-102.9.0-112.153.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'MozillaFirefox-translations-common-102.9.0-112.153.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'MozillaFirefox-102.9.0-112.153.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'MozillaFirefox-devel-102.9.0-112.153.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'MozillaFirefox-translations-common-102.9.0-112.153.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'MozillaFirefox-102.9.0-112.153.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'MozillaFirefox-devel-102.9.0-112.153.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'MozillaFirefox-translations-common-102.9.0-112.153.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-devel / etc');
}
