#
# (C) Tenable Network Security, Inc.
#
# References
# [also vulnerable to a heap overflow]
# Date:  Mon, 28 May 2001 18:16:57 -0400 (EDT)
# From: "Michal Zalewski" <lcamtuf@bos.bindview.com>
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: Unsafe Signal Handling in Sendmail
#

include("compat.inc");

if (description)
{
  script_id(10729);
  script_version("1.24");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-2001-0653");
  script_bugtraq_id(3163);

  script_name(english:"Sendmail < 8.11.6 -d category Value Local Overflow");
  script_summary(english:"Check Sendmail version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a privilege escalation attack.");
  script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number, may be
vulnerable to a local buffer overflow allowing local users to gain
root privileges.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.12beta19 or 8.11.6.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-0653");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/23");

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

constraints = [{ "fixed_version" : "8.11.6" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
