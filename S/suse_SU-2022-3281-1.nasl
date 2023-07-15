#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3281-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165233);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-2200",
    "CVE-2022-2226",
    "CVE-2022-2505",
    "CVE-2022-3032",
    "CVE-2022-3033",
    "CVE-2022-3034",
    "CVE-2022-31744",
    "CVE-2022-34468",
    "CVE-2022-34470",
    "CVE-2022-34472",
    "CVE-2022-34478",
    "CVE-2022-34479",
    "CVE-2022-34481",
    "CVE-2022-34484",
    "CVE-2022-36059",
    "CVE-2022-36314",
    "CVE-2022-36318",
    "CVE-2022-36319",
    "CVE-2022-38472",
    "CVE-2022-38473",
    "CVE-2022-38476",
    "CVE-2022-38477",
    "CVE-2022-38478"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3281-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : MozillaThunderbird (SUSE-SU-2022:3281-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3281-1 advisory.

  - If an object prototype was corrupted by an attacker, they would have been able to set undesired attributes
    on a JavaScript object, leading to privileged code execution. This vulnerability affects Firefox < 102,
    Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-2200)

  - An OpenPGP digital signature includes information about the date when the signature was created. When
    displaying an email that contains a digital signature, the email's date will be shown. If the dates were
    different, then Thunderbird didn't report the email as having an invalid signature. If an attacker
    performed a replay attack, in which an old email with old contents are resent at a later time, it could
    lead the victim to believe that the statements in the email are current. Fixed versions of Thunderbird
    will require that the signature's date roughly matches the displayed date of the email. This vulnerability
    affects Thunderbird < 102 and Thunderbird < 91.11. (CVE-2022-2226)

  - Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 102. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 102.1, Firefox <
    103, and Thunderbird < 102.1. (CVE-2022-2505)

  - When receiving an HTML email that contained an <code>iframe</code> element, which used a
    <code>srcdoc</code> attribute to define the inner HTML document, remote objects specified in the nested
    document, for example images or videos, were not blocked. Rather, the network was accessed, the objects
    were loaded and displayed. This vulnerability affects Thunderbird < 102.2.1 and Thunderbird < 91.13.1.
    (CVE-2022-3032)

  - If a Thunderbird user replied to a crafted HTML email containing a <code>meta</code> tag, with the
    <code>meta</code> tag having the <code>http-equiv=refresh</code> attribute, and the content attribute
    specifying an URL, then Thunderbird started a network request to that URL, regardless of the configuration
    to block remote content. In combination with certain other HTML elements and attributes in the email, it
    was possible to execute JavaScript code included in the message in the context of the message compose
    document. The JavaScript code was able to perform actions including, but probably not limited to, read and
    modify the contents of the message compose document, including the quoted original message, which could
    potentially contain the decrypted plaintext of encrypted data in the crafted email. The contents could
    then be transmitted to the network, either to the URL specified in the META refresh tag, or to a different
    URL, as the JavaScript code could modify the URL specified in the document. This bug doesn't affect users
    who have changed the default Message Body display setting to 'simple html' or 'plain text'. This
    vulnerability affects Thunderbird < 102.2.1 and Thunderbird < 91.13.1. (CVE-2022-3033)

  - When receiving an HTML email that specified to load an <code>iframe</code> element from a remote location,
    a request to the remote document was sent. However, Thunderbird didn't display the document. This
    vulnerability affects Thunderbird < 102.2.1 and Thunderbird < 91.13.1. (CVE-2022-3034)

  - An attacker could have injected CSS into stylesheets accessible via internal URIs, such as resource:, and
    in doing so bypass a page's Content Security Policy. This vulnerability affects Firefox ESR < 91.11,
    Thunderbird < 102, Thunderbird < 91.11, and Firefox < 101. (CVE-2022-31744)

  - An iframe that was not permitted to run scripts could do so if the user clicked on a
    <code>javascript:</code> link. This vulnerability affects Firefox < 102, Firefox ESR < 91.11, Thunderbird
    < 102, and Thunderbird < 91.11. (CVE-2022-34468)

  - Session history navigations may have led to a use-after-free and potentially exploitable crash. This
    vulnerability affects Firefox < 102, Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11.
    (CVE-2022-34470)

  - If there was a PAC URL set and the server that hosts the PAC was not reachable, OCSP requests would have
    been blocked, resulting in incorrect error pages being shown. This vulnerability affects Firefox < 102,
    Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34472)

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

  - In the <code>nsTArray_Impl::ReplaceElementsAt()</code> function, an integer overflow could have occurred
    when the number of elements to replace was too large for the container. This vulnerability affects Firefox
    < 102, Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34481)

  - The Mozilla Fuzzing Team reported potential vulnerabilities present in Thunderbird 91.10. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 102, Firefox ESR < 91.11,
    Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34484)

  - Mozilla: Matrix SDK bundled with Thunderbird vulnerable to denial-of-service attack (CVE-2022-36059)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203007");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012251.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5aa886c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34470");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36314");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38478");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaThunderbird, MozillaThunderbird-translations-common and / or MozillaThunderbird-translations-
other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38478");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-other");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaThunderbird-102.2.2-150200.8.82.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.2.2-150200.8.82.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.2.2-150200.8.82.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaThunderbird / MozillaThunderbird-translations-common / etc');
}
