#
# (C) Tenable Network Security, Inc.
#
# Ref:
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: sendmail -bt negative index bug...
# From: Michal Zalewski <lcamtuf@DIONE.IDS.PL>
# Date: Sun, 8 Oct 2000 15:12:46 +0200 
#


include("compat.inc");

if (description)
{
  script_id(10809);
  script_version("1.26");
  script_cvs_date("Date: 2018/11/15 20:50:24");

  script_name(english:"Sendmail < 8.11.2 -bt Option Local Overflow");
  script_summary(english:"Checks the version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is reportedly affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number, may be
vulnerable to a '-bt' overflow attack that allows a local user to
execute arbitrary commands as root.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Oct/120");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Jan/12");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail version 8.11.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"local user, arbitrary code execution");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/11/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "fixed_version" : "8.11.2" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
