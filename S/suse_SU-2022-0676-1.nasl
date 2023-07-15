#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0676-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158568);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2022-22753",
    "CVE-2022-22754",
    "CVE-2022-22756",
    "CVE-2022-22759",
    "CVE-2022-22760",
    "CVE-2022-22761",
    "CVE-2022-22763",
    "CVE-2022-22764"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0676-1");
  script_xref(name:"IAVA", value:"2022-A-0079-S");

  script_name(english:"SUSE SLES15 Security Update : MozillaFirefox (SUSE-SU-2022:0676-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0676-1 advisory.

  - A Time-of-Check Time-of-Use bug existed in the Maintenance (Updater) Service that could be abused to grant
    Users write access to an arbitrary directory. This could have been used to escalate to SYSTEM
    access.<br>*This bug only affects Firefox on Windows. Other operating systems are unaffected.*. This
    vulnerability affects Firefox < 97, Thunderbird < 91.6, and Firefox ESR < 91.6. (CVE-2022-22753)

  - If a user installed an extension of a particular type, the extension could have auto-updated itself and
    while doing so, bypass the prompt which grants the new version the new requested permissions. This
    vulnerability affects Firefox < 97, Thunderbird < 91.6, and Firefox ESR < 91.6. (CVE-2022-22754)

  - If a user was convinced to drag and drop an image to their desktop or other folder, the resulting object
    could have been changed into an executable script which would have run arbitrary code after the user
    clicked on it. This vulnerability affects Firefox < 97, Thunderbird < 91.6, and Firefox ESR < 91.6.
    (CVE-2022-22756)

  - If a document created a sandboxed iframe without <code>allow-scripts</code>, and subsequently appended an
    element to the iframe's document that e.g. had a JavaScript event handler - the event handler would have
    run despite the iframe's sandbox. This vulnerability affects Firefox < 97, Thunderbird < 91.6, and Firefox
    ESR < 91.6. (CVE-2022-22759)

  - When importing resources using Web Workers, error messages would distinguish the difference between
    <code>application/javascript</code> responses and non-script responses. This could have been abused to
    learn information cross-origin. This vulnerability affects Firefox < 97, Thunderbird < 91.6, and Firefox
    ESR < 91.6. (CVE-2022-22760)

  - Web-accessible extension pages (pages with a moz-extension:// scheme) were not correctly enforcing the
    frame-ancestors directive when it was used in the Web Extension's Content Security Policy. This
    vulnerability affects Firefox < 97, Thunderbird < 91.6, and Firefox ESR < 91.6. (CVE-2022-22761)

  - When a worker is shutdown, it was possible to cause script to run late in the lifecycle, at a point after
    where it should not be possible. This vulnerability affects Firefox < 96, Thunderbird < 91.6, and Firefox
    ESR < 91.6. (CVE-2022-22763)

  - Mozilla developers Paul Adenot and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox
    96 and Firefox ESR 91.5. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects
    Firefox < 97, Thunderbird < 91.6, and Firefox ESR < 91.6. (CVE-2022-22764)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195682");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010331.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb4985c1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22764");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-devel, MozillaFirefox-translations-common and / or MozillaFirefox-
translations-other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'MozillaFirefox-91.6.0-150.18.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'MozillaFirefox-devel-91.6.0-150.18.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'MozillaFirefox-translations-common-91.6.0-150.18.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'MozillaFirefox-translations-other-91.6.0-150.18.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.1']}
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
