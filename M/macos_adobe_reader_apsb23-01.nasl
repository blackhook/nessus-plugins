#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169878);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id(
    "CVE-2023-21579",
    "CVE-2023-21581",
    "CVE-2023-21585",
    "CVE-2023-21586",
    "CVE-2023-21604",
    "CVE-2023-21605",
    "CVE-2023-21606",
    "CVE-2023-21607",
    "CVE-2023-21608",
    "CVE-2023-21609",
    "CVE-2023-21610",
    "CVE-2023-21611",
    "CVE-2023-21612",
    "CVE-2023-21613",
    "CVE-2023-21614",
    "CVE-2023-22240",
    "CVE-2023-22241",
    "CVE-2023-22242"
  );
  script_xref(name:"IAVA", value:"2023-A-0019-S");

  script_name(english:"Adobe Reader < 20.005.30436 / 22.003.20310 Multiple Vulnerabilities (APSB23-01) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 20.005.30436 or 22.003.20310. It
is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat Reader versions 22.002.20212 (and earlier) and 20.005.30381 (and earlier) are affected by a
    Use After Free vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage
    this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2022-38437)

  - Integer Overflow or Wraparound (CWE-190) potentially leading to Arbitrary code execution (CVE-2023-21579)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory Leak (CVE-2023-21581, CVE-2023-21585)

  - NULL Pointer Dereference (CWE-476) potentially leading to Application denial-of-service (CVE-2023-21586)

  - Stack-based Buffer Overflow (CWE-121) potentially leading to Arbitrary code execution (CVE-2023-21604,
    CVE-2023-21610)

  - Heap-based Buffer Overflow (CWE-122) potentially leading to Arbitrary code execution (CVE-2023-21605)

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2023-21606,
    CVE-2023-21609)

  - Improper Input Validation (CWE-20) potentially leading to Arbitrary code execution (CVE-2023-21607)

  - Use After Free (CWE-416) potentially leading to Arbitrary code execution (CVE-2023-21608)

  - Violation of Secure Design Principles (CWE-657) potentially leading to Privilege escalation
    (CVE-2023-21611, CVE-2023-21612)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory leak (CVE-2023-21613, CVE-2023-21614)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 20.005.30436 / 22.003.20310 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22242");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 121, 122, 125, 190, 416, 476, 657, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Adobe Reader');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '15.7', 'max_version' : '22.003.20282', 'fixed_version' : '22.003.20310' },
  { 'min_version' : '20.1', 'max_version' : '20.005.30418', 'fixed_version' : '20.005.30436' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
