##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163030);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id(
    "CVE-2022-34215",
    "CVE-2022-34216",
    "CVE-2022-34217",
    "CVE-2022-34219",
    "CVE-2022-34220",
    "CVE-2022-34221",
    "CVE-2022-34222",
    "CVE-2022-34223",
    "CVE-2022-34224",
    "CVE-2022-34225",
    "CVE-2022-34226",
    "CVE-2022-34227",
    "CVE-2022-34228",
    "CVE-2022-34229",
    "CVE-2022-34230",
    "CVE-2022-34232",
    "CVE-2022-34233",
    "CVE-2022-34234",
    "CVE-2022-34236",
    "CVE-2022-34237",
    "CVE-2022-34238",
    "CVE-2022-34239",
    "CVE-2022-35669"
  );
  script_xref(name:"IAVA", value:"2022-A-0276-S");

  script_name(english:"Adobe Reader < 17.012.30249 / 20.005.30362 / 22.001.20169 Multiple Vulnerabilities (APSB22-32) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 17.012.30249, 20.005.30362, or
22.001.20169. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat Reader versions 22.001.20142 (and earlier), 20.005.30334 (and earlier) and 17.012.30229 (and
    earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in
    the context of the current user. Exploitation of this issue requires user interaction in that a victim
    must open a malicious file. (CVE-2022-34216, CVE-2022-34219, CVE-2022-34220, CVE-2022-34223,
    CVE-2022-34225, CVE-2022-34229, CVE-2022-34230)

  - Adobe Acrobat Reader versions 22.001.20142 (and earlier), 20.005.30334 (and earlier) and 17.012.30229 (and
    earlier) are affected by an out-of-bounds read vulnerability when parsing a crafted file, which could
    result in a read past the end of an allocated memory structure. An attacker could leverage this
    vulnerability to execute code in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2022-34215, CVE-2022-34222, CVE-2022-34226)

  - Adobe Acrobat Reader versions 22.001.20142 (and earlier), 20.005.30334 (and earlier) and 17.012.30229 (and
    earlier) are affected by an Out-Of-Bounds Write vulnerability that could result in arbitrary code
    execution in the context of the current user. Exploitation of this issue requires user interaction in that
    a victim must open a malicious file. (CVE-2022-34217)

  - Adobe Acrobat Reader versions 22.001.20142 (and earlier), 20.005.30334 (and earlier) and 17.012.30229 (and
    earlier) are affected by an Access of Resource Using Incompatible Type ('Type Confusion') vulnerability
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2022-34221)

  - Adobe Acrobat Reader versions 22.001.20142 (and earlier), 20.005.30334 (and earlier) and 17.012.30229 (and
    earlier) are affected by an Access of Uninitialized Pointer vulnerability that could result in arbitrary
    code execution in the context of the current user. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2022-34228)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-32.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 17.012.30249 / 20.005.30362 / 22.001.20169 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 416, 787, 824, 843);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Adobe Reader');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '15.7', 'max_version' : '22.001.20142', 'fixed_version' : '22.001.20169' },
  { 'min_version' : '20.1', 'max_version' : '20.005.30334', 'fixed_version' : '20.005.30362' },
  { 'min_version' : '17.8', 'max_version' : '17.012.30229', 'fixed_version' : '17.012.30249' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
