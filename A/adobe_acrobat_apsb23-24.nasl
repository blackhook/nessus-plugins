#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174136);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2023-26395",
    "CVE-2023-26396",
    "CVE-2023-26397",
    "CVE-2023-26405",
    "CVE-2023-26406",
    "CVE-2023-26407",
    "CVE-2023-26408",
    "CVE-2023-26417",
    "CVE-2023-26418",
    "CVE-2023-26419",
    "CVE-2023-26420",
    "CVE-2023-26421",
    "CVE-2023-26422",
    "CVE-2023-26423",
    "CVE-2023-26424",
    "CVE-2023-26425"
  );
  script_xref(name:"IAVA", value:"2023-A-0194");

  script_name(english:"Adobe Acrobat < 20.005.30467 / 23.001.20143 Multiple Vulnerabilities (APSB23-24)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a version prior to 20.005.30467 or 23.001.20143. It
is, therefore, affected by multiple vulnerabilities.

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2023-26395)

  - Violation of Secure Design Principles (CWE-657) potentially leading to Privilege escalation
    (CVE-2023-26396)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory leak (CVE-2023-26397)

  - Improper Input Validation (CWE-20) potentially leading to Arbitrary code execution (CVE-2023-26405,
    CVE-2023-26407)

  - Improper Access Control (CWE-284) potentially leading to Security feature bypass (CVE-2023-26406,
    CVE-2023-26408)

  - Use After Free (CWE-416) potentially leading to Arbitrary code execution (CVE-2023-26417, CVE-2023-26418,
    CVE-2023-26419, CVE-2023-26420, CVE-2023-26422, CVE-2023-26423, CVE-2023-26424)

  - Integer Underflow (Wrap or Wraparound) (CWE-191) potentially leading to Arbitrary code execution
    (CVE-2023-26421)

  - Out-of-bounds Read (CWE-125) potentially leading to Arbitrary code execution (CVE-2023-26425)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 20.005.30467 / 23.001.20143 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26425");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 191, 20, 284, 416, 657, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe Acrobat', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '15.7', 'max_version' : '23.001.20093', 'fixed_version' : '23.001.20143' },
  { 'min_version' : '20.1', 'max_version' : '20.005.30441', 'fixed_version' : '20.005.30467' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
