#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106870);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-14593", "CVE-2017-17458", "CVE-2017-17831");
  script_bugtraq_id(102926);
  script_xref(name:"IAVA", value:"2018-A-0056");

  script_name(english:"Atlassian SourceTree 0.5.1.0 < 2.4.7.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Atlassian SourceTree.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian SourceTree installed on the remote Windows
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian SourceTree installed on the remote Windows
host is a version 0.5.1.0 prior to 2.4.7.0. It is, therefore, affected
by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://confluence.atlassian.com/sourcetreekb/sourcetree-security-advisory-2018-01-24-942834324.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian SourceTree 2.4.7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:sourcetree");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atlassian_sourcetree_detect.nbin");
  script_require_keys("installed_sw/SourceTree");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::get_app_info(app:"SourceTree");

constraints = [{ "min_version" : "0.5.1.0", "fixed_version" : "2.4.7.0" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
