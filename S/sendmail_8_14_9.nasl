#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74289);
  script_version("1.6");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-2014-3956");
  script_bugtraq_id(67791);

  script_name(english:"Sendmail < 8.14.9 close-on-exec SMTP Connection Manipulation");
  script_summary(english:"Checks Sendmail version");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an SMTP connection manipulation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote mail server is running a version of Sendmail prior to
8.14.9. It is, therefore, affected by a flaw related to file
descriptors and the 'close-on-exec' flag that may allow a local
attacker to cause unspecified impact on open SMTP connections.");
  script_set_attribute(attribute:"see_also", value:"http://www.sendmail.org/releases/8.14.9");
  script_set_attribute(attribute:"see_also", value:"http://freecode.com/projects/sendmail/releases/363923");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.14.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3956");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "fixed_version" : "8.14.9" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
