#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:1817-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(174157);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2023-1945",
    "CVE-2023-29531",
    "CVE-2023-29532",
    "CVE-2023-29533",
    "CVE-2023-29535",
    "CVE-2023-29536",
    "CVE-2023-29539",
    "CVE-2023-29541",
    "CVE-2023-29542",
    "CVE-2023-29545",
    "CVE-2023-29548",
    "CVE-2023-29550"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:1817-1");
  script_xref(name:"IAVA", value:"2023-A-0182-S");

  script_name(english:"SUSE SLES15 Security Update : MozillaFirefox (SUSE-SU-2023:1817-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2023:1817-1 advisory.

  - Unexpected data returned from the Safe Browsing API could have led to memory corruption and a potentially
    exploitable crash.  (CVE-2023-1945)

  - An attacker could have caused an out of bounds memory access using WebGL APIs, leading to memory
    corruption and a potentially exploitable crash. This bug only affects Firefox for macOS. Other operating
    systems are unaffected.  (CVE-2023-29531)

  - A local attacker can trick the Mozilla Maintenance Service into applying an unsigned update file by
    pointing the service at an update file on a malicious SMB server. The update file can be replaced after
    the signature check, before the use, because the write-lock requested by the service does not work on a
    SMB server. Note: This attack requires local system access and only affects Windows. Other operating
    systems are not affected.  (CVE-2023-29532)

  - A website could have obscured the fullscreen notification by using a combination of
    <code>window.open</code>, fullscreen requests, <code>window.name</code> assignments, and
    <code>setInterval</code> calls. This could have led to user confusion and possible spoofing attacks.
    (CVE-2023-29533)

  - Following a Garbage Collector compaction, weak maps may have been accessed before they were correctly
    traced. This resulted in memory corruption and a potentially exploitable crash.  (CVE-2023-29535)

  - An attacker could cause the memory manager to incorrectly free a pointer that addresses attacker-
    controlled memory, resulting in an assertion, memory corruption, or a potentially exploitable crash.
    (CVE-2023-29536)

  - When handling the filename directive in the Content-Disposition header, the filename would be truncated if
    the filename contained a NULL character. This could have led to reflected file download attacks
    potentially tricking users to install malware.  (CVE-2023-29539)

  - Firefox did not properly handle downloads of files ending in <code>.desktop</code>, which can be
    interpreted to run attacker-controlled commands.  This bug only affects Firefox for Linux on certain
    Distributions. Other operating systems are unaffected, and Mozilla is unable to enumerate all affected
    Linux Distributions.  (CVE-2023-29541)

  - A newline in a filename could have been used to bypass the file extension security mechanisms that replace
    malicious file extensions such as .lnk  with .download. This could have led to accidental execution of
    malicious code. This bug only affects Firefox on Windows. Other versions of Firefox are unaffected.
    (CVE-2023-29542)

  - Similar to CVE-2023-28163, this time when choosing 'Save Link As', suggested filenames containing
    environment variable names would have resolved those in the context of the current user.  This bug only
    affects Firefox on Windows. Other versions of Firefox are unaffected.  (CVE-2023-29545)

  - A wrong lowering instruction in the ARM64 Ion compiler resulted in a wrong optimization result.
    (CVE-2023-29548)

  - Mozilla developers Randell Jesup, Andrew Osmond, Sebastian Hengst, Andrew McCreight, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 111 and Firefox ESR 102.9. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code.  (CVE-2023-29550)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210212");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-April/014444.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2febc079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29550");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-devel, MozillaFirefox-translations-common and / or MozillaFirefox-
translations-other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29550");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-29542");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/12");

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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'MozillaFirefox-devel-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'MozillaFirefox-translations-common-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'MozillaFirefox-translations-other-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'MozillaFirefox-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-devel-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-devel-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-translations-common-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-translations-common-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-translations-other-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-translations-other-102.10.0-150000.150.82.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'MozillaFirefox-102.10.0-150000.150.82.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'MozillaFirefox-devel-102.10.0-150000.150.82.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'MozillaFirefox-translations-common-102.10.0-150000.150.82.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'MozillaFirefox-translations-other-102.10.0-150000.150.82.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.1']}
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
