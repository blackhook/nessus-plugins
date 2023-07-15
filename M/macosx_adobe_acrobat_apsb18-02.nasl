#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106847);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/24");

  script_cve_id(
    "CVE-2018-4872",
    "CVE-2018-4879",
    "CVE-2018-4880",
    "CVE-2018-4881",
    "CVE-2018-4882",
    "CVE-2018-4883",
    "CVE-2018-4884",
    "CVE-2018-4885",
    "CVE-2018-4886",
    "CVE-2018-4887",
    "CVE-2018-4888",
    "CVE-2018-4889",
    "CVE-2018-4890",
    "CVE-2018-4891",
    "CVE-2018-4892",
    "CVE-2018-4893",
    "CVE-2018-4894",
    "CVE-2018-4895",
    "CVE-2018-4896",
    "CVE-2018-4897",
    "CVE-2018-4898",
    "CVE-2018-4899",
    "CVE-2018-4900",
    "CVE-2018-4901",
    "CVE-2018-4902",
    "CVE-2018-4903",
    "CVE-2018-4904",
    "CVE-2018-4905",
    "CVE-2018-4906",
    "CVE-2018-4907",
    "CVE-2018-4908",
    "CVE-2018-4909",
    "CVE-2018-4910",
    "CVE-2018-4911",
    "CVE-2018-4912",
    "CVE-2018-4913",
    "CVE-2018-4914",
    "CVE-2018-4915",
    "CVE-2018-4916",
    "CVE-2018-4917",
    "CVE-2018-4918",
    "CVE-2018-4997",
    "CVE-2018-4998",
    "CVE-2018-4999"
  );
  script_bugtraq_id(
    102992,
    102993,
    102994,
    102995,
    102996
  );

  script_name(english:"Adobe Acrobat < 2015.006.30416 / 2017.011.30078 / 2018.011.20035 Multiple Vulnerabilities (APSB18-02) (macOS)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS or Mac OS X
host is a version prior to 2015.006.30416, 2017.011.30078,
or 2018.011.20035. It is, therefore, affected by multiple
vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-02.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat 2015.006.30416 / 2017.011.30078
/ 2018.011.20035 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4872");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { "min_version" : "15.6", "fixed_version" : "15.6.30416" },
    { "min_version" : "17.8", "fixed_version" : "17.11.30078" },
    { "min_version" : "18.8", "fixed_version" : "18.11.20035" }
  ];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);