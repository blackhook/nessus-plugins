#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139579);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/26");

  script_cve_id(
    "CVE-2020-9693",
    "CVE-2020-9694",
    "CVE-2020-9695",
    "CVE-2020-9696",
    "CVE-2020-9697",
    "CVE-2020-9698",
    "CVE-2020-9699",
    "CVE-2020-9700",
    "CVE-2020-9701",
    "CVE-2020-9702",
    "CVE-2020-9703",
    "CVE-2020-9704",
    "CVE-2020-9705",
    "CVE-2020-9706",
    "CVE-2020-9707",
    "CVE-2020-9710",
    "CVE-2020-9711",
    "CVE-2020-9712",
    "CVE-2020-9713",
    "CVE-2020-9714",
    "CVE-2020-9715",
    "CVE-2020-9716",
    "CVE-2020-9717",
    "CVE-2020-9718",
    "CVE-2020-9719",
    "CVE-2020-9720",
    "CVE-2020-9721",
    "CVE-2020-9722",
    "CVE-2020-9723"
  );
  script_xref(name:"IAVA", value:"2020-A-0363-S");

  script_name(english:"Adobe Reader <= 2015.006.30523 / 2017.011.30171 / 2020.001.30002 / 2020.009.20074 Multiple Vulnerabilities (APSB20-48) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior or equal to 2015.006.30523,
2017.011.30171, 2020.001.30002, or 2020.009.20074. It is, therefore, affected by multiple vulnerabilities.

  - Disclosure of Sensitive Data potentially leading to
    Memory Leak (CVE-2020-9697)

  - Security bypass potentially leading to Privilege
    Escalation (CVE-2020-9714)

  - Out-of-bounds write potentially leading to Arbitrary
    Code Execution (CVE-2020-9693, CVE-2020-9694)

  - Security bypass potentially leading to Security feature
    bypass (CVE-2020-9696, CVE-2020-9712)

  - Stack exhaustion potentially leading to Application
    denial-of-service (CVE-2020-9702, CVE-2020-9703)

  - Out-of-bounds read potentially leading to Information
    disclosure (CVE-2020-9705, CVE-2020-9706, CVE-2020-9707,
    CVE-2020-9710, CVE-2020-9716, CVE-2020-9717,
    CVE-2020-9718, CVE-2020-9719, CVE-2020-9720,
    CVE-2020-9721, CVE-2020-9723)

  - Buffer error potentially leading to Arbitrary Code
    Execution (CVE-2020-9698, CVE-2020-9699, CVE-2020-9700,
    CVE-2020-9701, CVE-2020-9704)

  - Use-after-free potentially leading to Arbitrary Code
    Execution (CVE-2020-9715, CVE-2020-9722)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-48.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2015.006.30527 or 2017.011.30175 or 2020.001.30005 or 2020.012.20041 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9722");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

app_info = vcf::get_app_info(app:'Adobe Reader');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
constraints = [
  { 'min_version' : '15.6', 'max_version' : '15.006.30523', 'fixed_version' : '15.006.30527' },
  { 'min_version' : '15.7', 'max_version' : '20.009.20074', 'fixed_version' : '20.012.20041' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30171', 'fixed_version' : '17.011.30175' },
  { 'min_version' : '20.0', 'max_version' : '20.001.30002', 'fixed_version' : '20.001.30005' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);


