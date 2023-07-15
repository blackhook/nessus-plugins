#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111011);
  script_version("1.8");
  script_cvs_date("Date: 2019/04/05 23:25:09");

  script_cve_id(
    "CVE-2018-5009",
    "CVE-2018-5010",
    "CVE-2018-5011",
    "CVE-2018-5012",
    "CVE-2018-5014",
    "CVE-2018-5015",
    "CVE-2018-5016",
    "CVE-2018-5017",
    "CVE-2018-5018",
    "CVE-2018-5019",
    "CVE-2018-5020",
    "CVE-2018-5021",
    "CVE-2018-5022",
    "CVE-2018-5023",
    "CVE-2018-5024",
    "CVE-2018-5025",
    "CVE-2018-5026",
    "CVE-2018-5027",
    "CVE-2018-5028",
    "CVE-2018-5029",
    "CVE-2018-5030",
    "CVE-2018-5031",
    "CVE-2018-5032",
    "CVE-2018-5033",
    "CVE-2018-5034",
    "CVE-2018-5035",
    "CVE-2018-5036",
    "CVE-2018-5037",
    "CVE-2018-5038",
    "CVE-2018-5039",
    "CVE-2018-5040",
    "CVE-2018-5041",
    "CVE-2018-5042",
    "CVE-2018-5043",
    "CVE-2018-5044",
    "CVE-2018-5045",
    "CVE-2018-5046",
    "CVE-2018-5047",
    "CVE-2018-5048",
    "CVE-2018-5049",
    "CVE-2018-5050",
    "CVE-2018-5051",
    "CVE-2018-5052",
    "CVE-2018-5053",
    "CVE-2018-5054",
    "CVE-2018-5055",
    "CVE-2018-5056",
    "CVE-2018-5057",
    "CVE-2018-5058",
    "CVE-2018-5059",
    "CVE-2018-5060",
    "CVE-2018-5061",
    "CVE-2018-5062",
    "CVE-2018-5063",
    "CVE-2018-5064",
    "CVE-2018-5065",
    "CVE-2018-5066",
    "CVE-2018-5067",
    "CVE-2018-5068",
    "CVE-2018-5069",
    "CVE-2018-5070",
    "CVE-2018-12784",
    "CVE-2018-12754",
    "CVE-2018-12755",
    "CVE-2018-12756",
    "CVE-2018-12757",
    "CVE-2018-12758",
    "CVE-2018-12760",
    "CVE-2018-12761",
    "CVE-2018-12762",
    "CVE-2018-12763",
    "CVE-2018-12764",
    "CVE-2018-12765",
    "CVE-2018-12766",
    "CVE-2018-12767",
    "CVE-2018-12768",
    "CVE-2018-12770",
    "CVE-2018-12771",
    "CVE-2018-12772",
    "CVE-2018-12773",
    "CVE-2018-12774",
    "CVE-2018-12776",
    "CVE-2018-12777",
    "CVE-2018-12779",
    "CVE-2018-12780",
    "CVE-2018-12781",
    "CVE-2018-12782",
    "CVE-2018-12783",
    "CVE-2018-12785",
    "CVE-2018-12786",
    "CVE-2018-12787",
    "CVE-2018-12788",
    "CVE-2018-12789",
    "CVE-2018-12790",
    "CVE-2018-12791",
    "CVE-2018-12792",
    "CVE-2018-12793",
    "CVE-2018-12794",
    "CVE-2018-12795",
    "CVE-2018-12796",
    "CVE-2018-12797",
    "CVE-2018-12798",
    "CVE-2018-12802",
    "CVE-2018-12803"
  );
  script_bugtraq_id(
    104699,
    104700,
    104701,
    104704
  );

  script_name(english:"Adobe Acrobat < 15.006.30434 / 17.011.30096 / 18.011.20055 Multiple Vulnerabilities (APSB18-21)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a
version prior to 15.006.30434,  17.011.30096, or 18.011.20055. It is,
therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-21.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat 15.006.30434 / 17.011.30096 / 18.011.20055 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12782");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Adobe Acrobat", win_local:TRUE);
constraints = [
  { "min_version" : "15.6", "max_version" : "15.6.30418", "fixed_version" : "15.6.30434" },
  { "min_version" : "17.8", "max_version" : "17.11.30080", "fixed_version" : "17.11.30096" },
  { "min_version" : "15.7", "max_version" : "18.11.20040", "fixed_version" : "18.11.20055" }
];
# using adobe_reader namespace check_version_and_report to properly detect Continuous vs Classic, 
# and limit ver segments to 3 (18.x.y vs 18.x.y.12345) with max_segs:3
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
