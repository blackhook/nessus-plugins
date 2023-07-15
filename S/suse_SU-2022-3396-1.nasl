#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3396-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165487);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-2200",
    "CVE-2022-2505",
    "CVE-2022-34468",
    "CVE-2022-34469",
    "CVE-2022-34470",
    "CVE-2022-34471",
    "CVE-2022-34472",
    "CVE-2022-34473",
    "CVE-2022-34474",
    "CVE-2022-34475",
    "CVE-2022-34476",
    "CVE-2022-34477",
    "CVE-2022-34478",
    "CVE-2022-34479",
    "CVE-2022-34480",
    "CVE-2022-34481",
    "CVE-2022-34482",
    "CVE-2022-34483",
    "CVE-2022-34484",
    "CVE-2022-34485",
    "CVE-2022-36314",
    "CVE-2022-36318",
    "CVE-2022-36319",
    "CVE-2022-38472",
    "CVE-2022-38473",
    "CVE-2022-38476",
    "CVE-2022-38477",
    "CVE-2022-38478",
    "CVE-2022-40956",
    "CVE-2022-40957",
    "CVE-2022-40958",
    "CVE-2022-40959",
    "CVE-2022-40960",
    "CVE-2022-40962"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3396-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : MozillaFirefox (SUSE-SU-2022:3396-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3396-1 advisory.

  - If an object prototype was corrupted by an attacker, they would have been able to set undesired attributes
    on a JavaScript object, leading to privileged code execution. This vulnerability affects Firefox < 102,
    Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-2200)

  - Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 102. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 102.1, Firefox <
    103, and Thunderbird < 102.1. (CVE-2022-2505)

  - An iframe that was not permitted to run scripts could do so if the user clicked on a
    <code>javascript:</code> link. This vulnerability affects Firefox < 102, Firefox ESR < 91.11, Thunderbird
    < 102, and Thunderbird < 91.11. (CVE-2022-34468)

  - When a TLS Certificate error occurs on a domain protected by the HSTS header, the browser should not allow
    the user to bypass the certificate error. On Firefox for Android, the user was presented with the option
    to bypass the error; this could only have been done by the user explicitly. <br>*This bug only affects
    Firefox for Android. Other operating systems are unaffected.*. This vulnerability affects Firefox < 102.
    (CVE-2022-34469)

  - Session history navigations may have led to a use-after-free and potentially exploitable crash. This
    vulnerability affects Firefox < 102, Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11.
    (CVE-2022-34470)

  - When downloading an update for an addon, the downloaded addon update's version was not verified to match
    the version selected from the manifest. If the manifest had been tampered with on the server, an attacker
    could trick the browser into downgrading the addon to a prior version. This vulnerability affects Firefox
    < 102. (CVE-2022-34471)

  - If there was a PAC URL set and the server that hosts the PAC was not reachable, OCSP requests would have
    been blocked, resulting in incorrect error pages being shown. This vulnerability affects Firefox < 102,
    Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34472)

  - The HTML Sanitizer should have sanitized the <code>href</code> attribute of SVG <code><use></code>
    tags; however it incorrectly did not sanitize <code>xlink:href</code> attributes. This vulnerability
    affects Firefox < 102. (CVE-2022-34473)

  - Even when an iframe was sandboxed with <code>allow-top-navigation-by-user-activation</code>, if it
    received a redirect header to an external protocol the browser would process the redirect and prompt the
    user as appropriate. This vulnerability affects Firefox < 102. (CVE-2022-34474)

  - SVG <code><use></code> tags that referenced a same-origin document could have resulted in script
    execution if attacker input was sanitized via the HTML Sanitizer API. This would have required the
    attacker to reference a same-origin JavaScript file containing the script to be executed. This
    vulnerability affects Firefox < 102. (CVE-2022-34475)

  - ASN.1 parsing of an indefinite SEQUENCE inside an indefinite GROUP could have resulted in the parser
    accepting malformed ASN.1. This vulnerability affects Firefox < 102. (CVE-2022-34476)

  - The MediaError message property should be consistent to avoid leaking information about cross-origin
    resources; however for a same-site cross-origin resource, the message could have leaked information
    enabling XS-Leaks attacks. This vulnerability affects Firefox < 102. (CVE-2022-34477)

  - The <code>ms-msdt</code>, <code>search</code>, and <code>search-ms</code> protocols deliver content to
    Microsoft applications, bypassing the browser, when a user accepts a prompt. These applications have had
    known vulnerabilities, exploited in the wild (although we know of none exploited through Thunderbird), so
    in this release Thunderbird has blocked these protocols from prompting the user to open them.<br>*This bug
    only affects Thunderbird on Windows. Other operating systems are unaffected.*. This vulnerability affects
    Firefox < 102, Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34478)

  - A malicious website that could create a popup could have resized the popup to overlay the address bar with
    its own content, resulting in potential user confusion or spoofing attacks. <br>*This bug only affects
    Thunderbird for Linux. Other operating systems are unaffected.*. This vulnerability affects Firefox < 102,
    Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34479)

  - Within the <code>lg_init()</code> function, if several allocations succeed but then one fails, an
    uninitialized pointer would have been freed despite never being allocated. This vulnerability affects
    Firefox < 102. (CVE-2022-34480)

  - In the <code>nsTArray_Impl::ReplaceElementsAt()</code> function, an integer overflow could have occurred
    when the number of elements to replace was too large for the container. This vulnerability affects Firefox
    < 102, Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34481)

  - An attacker who could have convinced a user to drag and drop an image to a filesystem could have
    manipulated the resulting filename to contain an executable extension, and by extension potentially
    tricked the user into executing malicious code. While very similar, this is a separate issue from
    CVE-2022-34483. This vulnerability affects Firefox < 102. (CVE-2022-34482)

  - An attacker who could have convinced a user to drag and drop an image to a filesystem could have
    manipulated the resulting filename to contain an executable extension, and by extension potentially
    tricked the user into executing malicious code. While very similar, this is a separate issue from
    CVE-2022-34482. This vulnerability affects Firefox < 102. (CVE-2022-34483)

  - The Mozilla Fuzzing Team reported potential vulnerabilities present in Thunderbird 91.10. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 102, Firefox ESR < 91.11,
    Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34484)

  - Mozilla developers Bryce Seager van Dyk and the Mozilla Fuzzing Team reported potential vulnerabilities
    present in Firefox 101. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects
    Firefox < 102. (CVE-2022-34485)

  - When opening a Windows shortcut from the local filesystem, an attacker could supply a remote path that
    would lead to unexpected network requests from the operating system.<br>This bug only affects Firefox for
    Windows. Other operating systems are unaffected.*. This vulnerability affects Firefox ESR < 102.1, Firefox
    < 103, and Thunderbird < 102.1. (CVE-2022-36314)

  - When visiting directory listings for `chrome://` URLs as source text, some parameters were reflected. This
    vulnerability affects Firefox ESR < 102.1, Firefox ESR < 91.12, Firefox < 103, Thunderbird < 102.1, and
    Thunderbird < 91.12. (CVE-2022-36318)

  - When combining CSS properties for overflow and transform, the mouse cursor could interact with different
    coordinates than displayed. This vulnerability affects Firefox ESR < 102.1, Firefox ESR < 91.12, Firefox <
    103, Thunderbird < 102.1, and Thunderbird < 91.12. (CVE-2022-36319)

  - An attacker could have abused XSLT error handling to associate attacker-controlled content with another
    origin which was displayed in the address bar. This could have been used to fool the user into submitting
    data intended for the spoofed origin. This vulnerability affects Thunderbird < 102.2, Thunderbird < 91.13,
    Firefox ESR < 91.13, Firefox ESR < 102.2, and Firefox < 104. (CVE-2022-38472)

  - A cross-origin iframe referencing an XSLT document would inherit the parent domain's permissions (such as
    microphone or camera access). This vulnerability affects Thunderbird < 102.2, Thunderbird < 91.13, Firefox
    ESR < 91.13, Firefox ESR < 102.2, and Firefox < 104. (CVE-2022-38473)

  - A data race could occur in the <code>PK11_ChangePW</code> function, potentially leading to a use-after-
    free vulnerability. In Firefox, this lock protected the data when a user changed their master password.
    This vulnerability affects Firefox ESR < 102.2 and Thunderbird < 102.2. (CVE-2022-38476)

  - Mozilla developer Nika Layzell and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox
    103 and Firefox ESR 102.1. Some of these bugs showed evidence of memory corruption and we presume that
    with enough effort some of these could have been exploited to run arbitrary code. This vulnerability
    affects Firefox ESR < 102.2, Thunderbird < 102.2, and Firefox < 104. (CVE-2022-38477)

  - Members the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 103, Firefox ESR 102.1,
    and Firefox ESR 91.12. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects
    Thunderbird < 102.2, Thunderbird < 91.13, Firefox ESR < 91.13, Firefox ESR < 102.2, and Firefox < 104.
    (CVE-2022-38478)

  - When injecting an HTML base element, some requests would ignore the CSP's base-uri settings and accept the
    injected element's base instead. This vulnerability affects Firefox ESR < 102.3, Thunderbird < 102.3, and
    Firefox < 105. (CVE-2022-40956)

  - Inconsistent data in instruction and data cache when creating wasm code could lead to a potentially
    exploitable crash.<br>*This bug only affects Firefox on ARM64 platforms.*. This vulnerability affects
    Firefox ESR < 102.3, Thunderbird < 102.3, and Firefox < 105. (CVE-2022-40957)

  - By injecting a cookie with certain special characters, an attacker on a shared subdomain which is not a
    secure context could set and thus overwrite cookies from a secure context, leading to session fixation and
    other attacks. This vulnerability affects Firefox ESR < 102.3, Thunderbird < 102.3, and Firefox < 105.
    (CVE-2022-40958)

  - During iframe navigation, certain pages did not have their FeaturePolicy fully initialized leading to a
    bypass that leaked device permissions into untrusted subdocuments. This vulnerability affects Firefox ESR
    < 102.3, Thunderbird < 102.3, and Firefox < 105. (CVE-2022-40959)

  - Concurrent use of the URL parser with non-UTF-8 data was not thread-safe. This could lead to a use-after-
    free causing a potentially exploitable crash. This vulnerability affects Firefox ESR < 102.3, Thunderbird
    < 102.3, and Firefox < 105. (CVE-2022-40960)

  - Mozilla developers Nika Layzell, Timothy Nikkel, Sebastian Hengst, Andreas Pehrson, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 104 and Firefox ESR 102.2. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 102.3, Thunderbird < 102.3, and
    Firefox < 105. (CVE-2022-40962)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203477");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012383.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b6ce85f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34470");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34471");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34475");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34485");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36314");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40962");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38478");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-branding-upstream-102.3.0-150200.152.61.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-branding-upstream-102.3.0-150200.152.61.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-102.3.0-150200.152.61.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-branding-SLE-102-150200.9.10.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-devel-102.3.0-150200.152.61.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-102.3.0-150200.152.61.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-102.3.0-150200.152.61.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-branding-SLE / etc');
}
