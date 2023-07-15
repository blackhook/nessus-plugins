#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4462-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168715);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-46872",
    "CVE-2022-46874",
    "CVE-2022-46875",
    "CVE-2022-46878",
    "CVE-2022-46880",
    "CVE-2022-46881",
    "CVE-2022-46882"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4462-1");
  script_xref(name:"IAVA", value:"2022-A-0517-S");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : MozillaFirefox (SUSE-SU-2022:4462-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:4462-1 advisory.

  - An attacker who compromised a content process could have partially escaped the sandbox to read arbitrary
    files via clipboard-related IPC messages.<br>*This bug only affects Thunderbird for Linux. Other operating
    systems are unaffected.*. This vulnerability affects Firefox < 108, Firefox ESR < 102.6, and Thunderbird <
    102.6. (CVE-2022-46872)

  - A file with a long filename could have had its filename truncated to remove the valid extension, leaving a
    malicious extension in its place. This could potentially led to user confusion and the execution of
    malicious code.<br/>*Note*: This issue was originally included in the advisories for Thunderbird 102.6,
    but a patch (specific to Thunderbird) was omitted, resulting in it actually being fixed in Thunderbird
    102.6.1. This vulnerability affects Firefox < 108, Thunderbird < 102.6.1, Thunderbird < 102.6, and Firefox
    ESR < 102.6. (CVE-2022-46874)

  - The executable file warning was not presented when downloading .atloc and .ftploc files, which can run
    commands on a user's computer. <br>*Note: This issue only affected Mac OS operating systems. Other
    operating systems are unaffected.*. This vulnerability affects Firefox < 108, Firefox ESR < 102.6, and
    Thunderbird < 102.6. (CVE-2022-46875)

  - Mozilla developers Randell Jesup, Valentin Gosu, Olli Pettay, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Thunderbird 102.5. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 108, Firefox ESR < 102.6, and Thunderbird < 102.6. (CVE-2022-46878)

  - A missing check related to tex units could have led to a use-after-free and potentially exploitable
    crash.<br />*Note*: This advisory was added on December 13th, 2022 after we better understood the impact
    of the issue. The fix was included in the original release of Firefox 105. This vulnerability affects
    Firefox ESR < 102.6, Firefox < 105, and Thunderbird < 102.6. (CVE-2022-46880)

  - An optimization in WebGL was incorrect in some cases, and could have led to memory corruption and a
    potentially exploitable crash. This vulnerability affects Firefox < 106, Firefox ESR < 102.6, and
    Thunderbird < 102.6. (CVE-2022-46881)

  - A use-after-free in WebGL extensions could have led to a potentially exploitable crash. This vulnerability
    affects Firefox < 107, Firefox ESR < 102.6, and Thunderbird < 102.6. (CVE-2022-46882)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206242");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-December/013229.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7270537");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46882");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/14");

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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-branding-upstream-102.6.0-150200.152.70.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-branding-upstream-102.6.0-150200.152.70.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-102.6.0-150200.152.70.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-devel-102.6.0-150200.152.70.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-102.6.0-150200.152.70.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-102.6.0-150200.152.70.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-branding-upstream / etc');
}
