#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38877);
  script_version("1.18");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-2009-1490");
  script_bugtraq_id(34944);

  script_name(english:"Sendmail < 8.13.2 Mail X-Header Handling Remote Overflow");
  script_summary(english:"Checks the version of Sendmail");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Sendmail mail server
earlier than 8.13.2. Such versions are reportedly affected by a remote
buffer overflow vulnerability. An attacker could leverage this flaw to
execute arbitrary code with the privileges of the affected
application.");
  script_set_attribute(attribute:"see_also", value:"http://www.nmrc.org/~thegnome/blog/apr09/");
  script_set_attribute(attribute:"see_also", value:"http://www.sendmail.org/releases/8.13.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.13.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1490");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "fixed_version" : "8.13.2" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
