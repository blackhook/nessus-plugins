#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2019:14124-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150682);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-9811",
    "CVE-2019-11707",
    "CVE-2019-11708",
    "CVE-2019-11709",
    "CVE-2019-11711",
    "CVE-2019-11712",
    "CVE-2019-11713",
    "CVE-2019-11715",
    "CVE-2019-11717",
    "CVE-2019-11719",
    "CVE-2019-11729",
    "CVE-2019-11730"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2019:14124-1");
  script_xref(name:"IAVA", value:"2019-A-0231-S");
  script_xref(name:"IAVA", value:"2019-A-0207-S");
  script_xref(name:"IAVA", value:"2019-A-0211-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CEA-ID", value:"CEA-2019-0458");

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2019:14124-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2019:14124-1 advisory.

  - A type confusion vulnerability can occur when manipulating JavaScript objects due to issues in Array.pop.
    This can allow for an exploitable crash. We are aware of targeted attacks in the wild abusing this flaw.
    This vulnerability affects Firefox ESR < 60.7.1, Firefox < 67.0.3, and Thunderbird < 60.7.2.
    (CVE-2019-11707)

  - Insufficient vetting of parameters passed with the Prompt:Open IPC message between child and parent
    processes can result in the non-sandboxed parent process opening web content chosen by a compromised child
    process. When combined with additional vulnerabilities this could result in executing arbitrary code on
    the user's computer. This vulnerability affects Firefox ESR < 60.7.2, Firefox < 67.0.4, and Thunderbird <
    60.7.2. (CVE-2019-11708)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 67 and Firefox ESR
    60.7. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that
    some of these could be exploited to run arbitrary code. This vulnerability affects Firefox ESR < 60.8,
    Firefox < 68, and Thunderbird < 60.8. (CVE-2019-11709)

  - When an inner window is reused, it does not consider the use of document.domain for cross-origin
    protections. If pages on different subdomains ever cooperatively use document.domain, then either page can
    abuse this to inject script into arbitrary pages on the other subdomain, even those that did not use
    document.domain to relax their origin security. This vulnerability affects Firefox ESR < 60.8, Firefox <
    68, and Thunderbird < 60.8. (CVE-2019-11711)

  - POST requests made by NPAPI plugins, such as Flash, that receive a status 308 redirect response can bypass
    CORS requirements. This can allow an attacker to perform Cross-Site Request Forgery (CSRF) attacks. This
    vulnerability affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8. (CVE-2019-11712)

  - A use-after-free vulnerability can occur in HTTP/2 when a cached HTTP/2 stream is closed while still in
    use, resulting in a potentially exploitable crash. This vulnerability affects Firefox ESR < 60.8, Firefox
    < 68, and Thunderbird < 60.8. (CVE-2019-11713)

  - Due to an error while parsing page content, it is possible for properly sanitized user input to be
    misinterpreted and lead to XSS hazards on web sites in certain circumstances. This vulnerability affects
    Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8. (CVE-2019-11715)

  - A vulnerability exists where the caret (^) character is improperly escaped constructing some URIs due to
    it being used as a separator, allowing for possible spoofing of origin attributes. This vulnerability
    affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8. (CVE-2019-11717)

  - When importing a curve25519 private key in PKCS#8format with leading 0x00 bytes, it is possible to trigger
    an out-of-bounds read in the Network Security Services (NSS) library. This could lead to information
    disclosure. This vulnerability affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8.
    (CVE-2019-11719)

  - Empty or malformed p256-ECDH public keys may trigger a segmentation fault due values being improperly
    sanitized before being copied into memory and used. This vulnerability affects Firefox ESR < 60.8, Firefox
    < 68, and Thunderbird < 60.8. (CVE-2019-11729)

  - A vulnerability exists where if a user opens a locally saved HTML file, this file can use file: URIs to
    access other files in the same directory or sub-directories if the names are known or guessed. The Fetch
    API can then be used to read the contents of any files stored in these directories and they may uploaded
    to a server. It was demonstrated that in combination with a popular Android messaging app, if a malicious
    HTML attachment is sent to a user and they opened that attachment in Firefox, due to that app's
    predictable pattern for locally-saved file names, it is possible to read attachments the victim received
    from other correspondents. This vulnerability affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird <
    60.8. (CVE-2019-11730)

  - As part of a winning Pwn2Own entry, a researcher demonstrated a sandbox escape by installing a malicious
    language pack and then opening a browser feature that used the compromised translation. This vulnerability
    affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8. (CVE-2019-9811)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1137792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1138614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1138872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140868");
  # https://lists.suse.com/pipermail/sle-security-updates/2019-July/005727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?612b520c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11709");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9811");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-translations-common and / or MozillaFirefox-translations-other
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11708");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
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

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'MozillaFirefox-60.8.0esr-78.43', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-60.8.0esr-78.43', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-60.8.0esr-78.43', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-60.8.0esr-78.43', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-60.8.0esr-78.43', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-60.8.0esr-78.43', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
