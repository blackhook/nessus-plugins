#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3651-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155157);
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
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3651-1");
  script_xref(name:"IAVA", value:"2021-A-0527-S");

  script_name(english:"SUSE SLES15 Security Update : MozillaFirefox (SUSE-SU-2021:3651-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3651-1 advisory.

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
  # https://lists.suse.com/pipermail/sle-security-updates/2021-November/009712.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84e5f5bf");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38510");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-devel, MozillaFirefox-translations-common and / or MozillaFirefox-
translations-other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15.1'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15.1'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15.1'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15.1'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15.1'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15.1'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15.1'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15.1'},
    {'reference':'MozillaFirefox-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-15.1'},
    {'reference':'MozillaFirefox-devel-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-15.1'},
    {'reference':'MozillaFirefox-translations-common-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-15.1'},
    {'reference':'MozillaFirefox-translations-other-91.3.0-150.6.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-15.1'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
