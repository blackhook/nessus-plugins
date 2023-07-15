#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(120949);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-16011", "CVE-2018-16018");

  script_name(english:"Adobe Acrobat <= 2015.006.30461 / 2017.011.30110 / 2019.010.20064 Multiple Vulnerabilities (APSB19-02) (macOS)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a
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
"Upgrade to Adobe Acrobat 2015.006.30464 or 2017.011.30113 or
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.20zzz = DC Classic
# x.y.30zzz = DC Continuous
constraints = [
  { "min_version" : "15.6", "max_version" : "15.006.30461", "fixed_version" : "15.006.30464" },
  { "min_version" : "17.8", "max_version" : "17.011.30110", "fixed_version" : "17.011.30113" },
  { "min_version" : "15.8", "max_version" : "19.010.20064", "fixed_version" : "19.010.20069" }
];

vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
