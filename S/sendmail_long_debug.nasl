#
# (C) Tenable Network Security, Inc.
# Original script by Xue Yong Zhi <xueyong@udel.edu>
#
# Changes by Tenable:
# - Revised plugin title, output formatting (9/16/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)
# - rewritten by Tenable (7/23/2018)

include("compat.inc");

if (description)
{
  script_id(11348);
  script_version("1.10");
  script_cvs_date("Date: 2018/08/22 16:49:14");

  script_cve_id("CVE-1999-1309");

  script_name(english:"Sendmail < 8.6.8 -debug Local Privilege Escalation");
  script_summary(english:"Checks the version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number, allows
local users to gain root access via a large value in the debug (-d)
command line option.");
  script_set_attribute(attribute:"solution", value:
"Install Sendmail newer than versions 8.6.8 or install a vendor
supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-1309");
  script_set_attribute(attribute:"vuln_publication_date", value:"1994/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "fixed_version" : "8.6.8" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
