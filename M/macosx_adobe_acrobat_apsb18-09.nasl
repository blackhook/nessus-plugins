#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109897);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2018-4947",
    "CVE-2018-4948",
    "CVE-2018-4949",
    "CVE-2018-4950",
    "CVE-2018-4951",
    "CVE-2018-4952",
    "CVE-2018-4953",
    "CVE-2018-4954",
    "CVE-2018-4955",
    "CVE-2018-4956",
    "CVE-2018-4957",
    "CVE-2018-4958",
    "CVE-2018-4959",
    "CVE-2018-4960",
    "CVE-2018-4961",
    "CVE-2018-4962",
    "CVE-2018-4963",
    "CVE-2018-4964",
    "CVE-2018-4965",
    "CVE-2018-4966",
    "CVE-2018-4967",
    "CVE-2018-4968",
    "CVE-2018-4969",
    "CVE-2018-4970",
    "CVE-2018-4971",
    "CVE-2018-4972",
    "CVE-2018-4973",
    "CVE-2018-4974",
    "CVE-2018-4975",
    "CVE-2018-4976",
    "CVE-2018-4977",
    "CVE-2018-4978",
    "CVE-2018-4979",
    "CVE-2018-4980",
    "CVE-2018-4981",
    "CVE-2018-4982",
    "CVE-2018-4983",
    "CVE-2018-4984",
    "CVE-2018-4985",
    "CVE-2018-4986",
    "CVE-2018-4987",
    "CVE-2018-4988",
    "CVE-2018-4989",
    "CVE-2018-4990",
    "CVE-2018-4993",
    "CVE-2018-4995",
    "CVE-2018-4996",
    "CVE-2018-12812",
    "CVE-2018-12815"
  );
  script_bugtraq_id(
    104102,
    104167,
    104168,
    104169,
    104171,
    104172,
    104173,
    104174,
    104175,
    104176,
    104177
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Adobe Acrobat < 2015.006.30418 / 2017.011.30080 / 2018.011.20040 Multiple Vulnerabilities (APSB18-09) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS or Mac OS X
host is a version prior to 2015.006.30418, 2017.011.30080,
or 2018.011.20040. It is, therefore, affected by multiple
vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-09.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat 2015.006.30418 / 2017.011.30080
/ 2018.011.20040 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4996");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_acrobat_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Acrobat");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"Adobe Acrobat");

  constraints = [
    { "min_version" : "15.6", "fixed_version" : "15.6.30418" },
    { "min_version" : "17.8", "fixed_version" : "17.11.30080" },
    { "min_version" : "18.8", "fixed_version" : "18.11.20040" }
  ];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
