#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43637);
  script_version("1.20");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-2009-4565");
  script_bugtraq_id(37543);
  script_xref(name:"IAVA", value:"2010-A-0002");
  script_xref(name:"Secunia", value:"37998");

  script_name(english:"Sendmail < 8.14.4 SSL Certificate NULL Character Spoofing");
  script_summary(english:"Checks the version of Sendmail");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is susceptible to a man-in-the-middle attack.");
  script_set_attribute(attribute:"description", value:
"The remote mail server is running a version of Sendmail earlier than
8.14.4. Such versions are reportedly affected by a flaw that may allow
an attacker to spoof SSL certificates by using a NULL character in
certain certificate fields.

A remote attacker may exploit this to perform a man-in-the-middle
attack.");
  script_set_attribute(attribute:"see_also", value:"http://www.sendmail.org/releases/8.14.4");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.14.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-4565");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}
include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "fixed_version" : "8.14.4" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
