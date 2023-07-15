#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10588);
  script_version("1.17");
  script_cvs_date("Date: 2018/08/06 17:19:16");

  script_cve_id("CVE-1999-0206");

  script_name(english:"Sendmail mime7to8() Function Remote Overflow");
  script_summary(english:"Checks Sendmail version number");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number, may be
vulnerable to a MIME buffer overflow attack which allows anyone to
execute arbitrary commands as root.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Sendmail.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0206");
  script_set_attribute(attribute:"vuln_publication_date", value:"1996/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "min_version" : "8.8.0", "fixed_version" : "8.8.2" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
