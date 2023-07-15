#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102428);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-3016",
    "CVE-2017-3038",
    "CVE-2017-3113",
    "CVE-2017-3115",
    "CVE-2017-3116",
    "CVE-2017-3117",
    "CVE-2017-3118",
    "CVE-2017-3119",
    "CVE-2017-3120",
    "CVE-2017-3121",
    "CVE-2017-3122",
    "CVE-2017-3123",
    "CVE-2017-3124",
    "CVE-2017-11209",
    "CVE-2017-11210",
    "CVE-2017-11211",
    "CVE-2017-11212",
    "CVE-2017-11214",
    "CVE-2017-11216",
    "CVE-2017-11217",
    "CVE-2017-11218",
    "CVE-2017-11219",
    "CVE-2017-11220",
    "CVE-2017-11221",
    "CVE-2017-11222",
    "CVE-2017-11223",
    "CVE-2017-11224",
    "CVE-2017-11226",
    "CVE-2017-11227",
    "CVE-2017-11228",
    "CVE-2017-11229",
    "CVE-2017-11230",
    "CVE-2017-11231",
    "CVE-2017-11232",
    "CVE-2017-11233",
    "CVE-2017-11234",
    "CVE-2017-11235",
    "CVE-2017-11236",
    "CVE-2017-11237",
    "CVE-2017-11238",
    "CVE-2017-11239",
    "CVE-2017-11241",
    "CVE-2017-11242",
    "CVE-2017-11243",
    "CVE-2017-11244",
    "CVE-2017-11245",
    "CVE-2017-11246",
    "CVE-2017-11248",
    "CVE-2017-11249",
    "CVE-2017-11251",
    "CVE-2017-11252",
    "CVE-2017-11254",
    "CVE-2017-11255",
    "CVE-2017-11256",
    "CVE-2017-11257",
    "CVE-2017-11258",
    "CVE-2017-11259",
    "CVE-2017-11260",
    "CVE-2017-11261",
    "CVE-2017-11262",
    "CVE-2017-11263",
    "CVE-2017-11265",
    "CVE-2017-11267",
    "CVE-2017-11268",
    "CVE-2017-11269",
    "CVE-2017-11270",
    "CVE-2017-11271"
  );
  script_bugtraq_id(
    100179,
    100180,
    100181,
    100182,
    100184,
    100185,
    100186,
    100187,
    100189
  );

  script_name(english:"Adobe Reader < 11.0.21 / 2015.006.30355 / 2017.011.30066 / 2017.012.20098 Multiple Vulnerabilities (APSB17-24)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a
version prior to 11.0.21, 2015.006.30355, 2017.011.30066,
or 2017.012.20098. It is, therefore, affected by multiple
vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 11.0.21 / 2015.006.30355 / 2017.011.30066
/ 2017.012.20098 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3124");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::adobe_reader::get_app_info();
constraints = [
  { "min_version" : "11.0", "fixed_version" : "11.0.21" },
  { "min_version" : "15.6", "max_version" : "15.6.30306", "fixed_version" : "15.6.30355" },
  { "min_version" : "17.8", "max_version" : "17.8.30051", "fixed_version" : "17.11.30066" },
  { "min_version" : "15.7", "max_version" : "17.9.20058", "fixed_version" : "17.12.20098" }
];
# using adobe_reader namespace check_version_and_report to properly detect Continuous vs Classic, 
# and limit ver segments to 3 (18.x.y vs 18.x.y.12345) with max_segs:3
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
