#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(120952);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/31 15:18:52");

  script_cve_id("CVE-2018-16011", "CVE-2018-16018");

  script_name(english:"Adobe Reader <= 2015.006.30461 / 2017.011.30110 / 2019.010.20064 Multiple Vulnerabilities (APSB19-02)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a
version prior or equal to 2015.006.30461, 2017.011.30110, or
2019.010.20064. It is, therefore, affected by multiple
vulnerabilities : 

  - An unspecified use after free vulnerability. An authenticated,
    local attacker can exploit this to execute arbitrary code.
    (CVE-2018-16011)

  - An unspecified elevation of privilege vulnerability. An
    authenticated, local attacker can exploit this to gain elevated
    privileges. (CVE-2018-16018)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-02.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 2015.006.30464 or 2017.011.30113 or
2019.010.20069 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::adobe_reader::get_app_info();

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.20zzz = DC Classic
# x.y.30zzz = DC Continuous
constraints = [
  { "min_version" : "15.6", "max_version" : "15.006.30461", "fixed_version" : "15.006.30464" },
  { "min_version" : "17.8", "max_version" : "17.011.30110", "fixed_version" : "17.011.30113" },
  { "min_version" : "15.7", "max_version" : "19.010.20064", "fixed_version" : "19.010.20069" },
];
# using adobe_reader namespace check_version_and_report to properly detect Continuous vs Classic, 
# and limit ver segments to 3 (18.x.y vs 18.x.y.12345) with max_segs:3
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
