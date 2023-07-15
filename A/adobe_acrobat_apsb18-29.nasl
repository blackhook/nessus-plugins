#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111793);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-12799", "CVE-2018-12808");
  script_bugtraq_id(105069);

  script_name(english:"Adobe Acrobat <= 15.006.30434 / 17.011.30096 / 18.011.20055 Multiple Vulnerabilities (APSB18-29)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a
version prior or equal to 15.006.30434,  17.011.30096, or 18.011.20055. It is,
therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-29.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat 15.006.30448 / 17.011.30099 / 18.011.20058 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");

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
  { "min_version" : "15.6", "max_version":"15.6.30434", "fixed_version" : "15.6.30448" },
  { "min_version" : "17.8", "max_version":"17.11.30096", "fixed_version" : "17.11.30099" },
  { "min_version" : "15.7", "max_version":"18.11.20055", "fixed_version" : "18.11.20058" }
];
# using adobe_reader namespace check_version_and_report to properly detect Continuous vs Classic, 
# and limit ver segments to 3 (18.x.y vs 18.x.y.12345) with max_segs:3
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
