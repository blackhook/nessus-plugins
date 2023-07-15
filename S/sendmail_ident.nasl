#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10278);
  script_version("1.18");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-1999-0204");
  script_bugtraq_id(2311);

  script_name(english:"Sendmail 8.6.9 IDENT Remote Overflow");
  script_summary(english:"Check sendmail version number");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number, may be
vulnerable to the ident overflow which allows any remote attacker to
execute arbitrary commands as root.");
  script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of Sendmail.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0204");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1995/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2002-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "equal" : "8.6.9" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
