#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14290-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150679);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2020-6796",
    "CVE-2020-6797",
    "CVE-2020-6798",
    "CVE-2020-6799",
    "CVE-2020-6800"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14290-1");
  script_xref(name:"IAVA", value:"2020-A-0072-S");

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2020:14290-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14290-1 advisory.

  - A content process could have modified shared memory relating to crash reporting information, crash itself,
    and cause an out-of-bound write. This could have caused memory corruption and a potentially exploitable
    crash. This vulnerability affects Firefox < 73 and Firefox < ESR68.5. (CVE-2020-6796)

  - By downloading a file with the .fileloc extension, a semi-privileged extension could launch an arbitrary
    application on the user's computer. The attacker is restricted as they are unable to download non-
    quarantined files or supply command line arguments to the application, limiting the impact. Note: this
    issue only occurs on Mac OSX. Other operating systems are unaffected. This vulnerability affects
    Thunderbird < 68.5, Firefox < 73, and Firefox < ESR68.5. (CVE-2020-6797)

  - If a template tag was used in a select tag, the parser could be confused and allow JavaScript parsing and
    execution when it should not be allowed. A site that relied on the browser behaving correctly could suffer
    a cross-site scripting vulnerability as a result. In general, this flaw cannot be exploited through email
    in the Thunderbird product because scripting is disabled when reading mail, but is potentially a risk in
    browser or browser-like contexts. This vulnerability affects Thunderbird < 68.5, Firefox < 73, and Firefox
    < ESR68.5. (CVE-2020-6798)

  - Command line arguments could have been injected during Firefox invocation as a shell handler for certain
    unsupported file types. This required Firefox to be configured as the default handler for a given file
    type and for a file downloaded to be opened in a third party application that insufficiently sanitized URL
    data. In that situation, clicking a link in the third party application could have been used to retrieve
    and execute files whose location was supplied through command line arguments. Note: This issue only
    affects Windows operating systems and when Firefox is configured as the default handler for non-default
    filetypes. Other operating systems are unaffected. This vulnerability affects Firefox < 73 and Firefox <
    ESR68.5. (CVE-2020-6799)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 72 and Firefox ESR
    68.4. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. In general, these flaws cannot be exploited
    through email in the Thunderbird product because scripting is disabled when reading mail, but are
    potentially risks in browser or browser-like contexts. This vulnerability affects Thunderbird < 68.5,
    Firefox < 73, and Firefox < ESR68.5. (CVE-2020-6800)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1163368");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-February/006514.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7f84073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-6796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-6797");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-6798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-6799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-6800");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-translations-common and / or MozillaFirefox-translations-other
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'MozillaFirefox-68.5.0-78.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-68.5.0-78.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-68.5.0-78.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-68.5.0-78.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-68.5.0-78.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-68.5.0-78.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
      severity   : SECURITY_WARNING,
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
