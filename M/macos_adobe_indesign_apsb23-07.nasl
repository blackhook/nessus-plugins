#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169887);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id(
    "CVE-2023-21587",
    "CVE-2023-21588",
    "CVE-2023-21589",
    "CVE-2023-21590",
    "CVE-2023-21591",
    "CVE-2023-21592"
  );
  script_xref(name:"IAVA", value:"2023-A-0020-S");

  script_name(english:"Adobe InDesign < 17.4.1 / 18.0 < 18.1 Multiple Vulnerabilities (APSB23-07) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote macOS host is prior to 17.4.1, 18.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB23-07 advisory.

  - PhantomJS through 2.1.1 has an arbitrary file read vulnerability, as demonstrated by an XMLHttpRequest for
    a file:// URI. The vulnerability exists in the page.open() function of the webpage module, which loads a
    specified URL and calls a given callback. An attacker can supply a specially crafted HTML file, as user
    input, that allows reading arbitrary files on the filesystem. For example, if page.render() is the
    function callback, this generates a PDF or an image of the targeted file. NOTE: this product is no longer
    developed. (CVE-2019-17221)

  - Adobe Experience Manager versions 6.5.13.0 (and earlier) is affected by a reflected Cross-Site Scripting
    (XSS) vulnerability. If an attacker is able to convince a victim to visit a URL referencing a vulnerable
    page, malicious JavaScript content may be executed within the context of the victim's browser.
    Exploitation of this issue requires low-privilege access to AEM. (CVE-2022-28851)

  - Adobe InDesign versions 17.2.1 (and earlier) and 16.4.1 (and earlier) are affected by a Heap-based Buffer
    Overflow vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-34245, CVE-2022-34246)

  - Adobe InDesign versions 17.2.1 (and earlier) and 16.4.1 (and earlier) are affected by an Out-Of-Bounds
    Write vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-34247)

  - Adobe InDesign versions 17.2.1 (and earlier) and 16.4.1 (and earlier) are affected by an out-of-bounds
    read vulnerability when parsing a crafted file, which could result in a read past the end of an allocated
    memory structure. An attacker could leverage this vulnerability to execute code in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2022-34248)

  - Heap-based Buffer Overflow (CWE-122) potentially leading to Arbitrary code execution (CVE-2023-21587)

  - Improper Input Validation (CWE-20) potentially leading to Arbitrary code execution (CVE-2023-21588)

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2023-21589,
    CVE-2023-21590)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory Leak (CVE-2023-21591, CVE-2023-21592)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb23-07.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 17.4.1, 18.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21590");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 122, 125, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_indesign_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe InDesign");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe InDesign');

var constraints = [
  { 'fixed_version' : '17.4.1', 'fixed_display' : 'Release: ID17.4.1' },
  { 'min_version' : '18.0', 'fixed_version' : '18.1', 'fixed_display' : 'Release: ID18.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
