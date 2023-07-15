#
# (C) Tenable Network Security, Inc.
# Original script by Xue Yong Zhi <xueyong@udel.edu>
#
# Changes by Tenable:
# - Revised plugin title, output formatting (9/14/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)
# - rewritten by Tenable (7/23/2018)

include("compat.inc");

if (description)
{
  script_id(11351);
  script_version("1.18");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-2000-0319");
  script_bugtraq_id(1146);

  script_name(english:"Sendmail < 8.10.0 mail.local Newline Handling Remote DoS");
  script_summary(english:"Checks the version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"mail.local in the remote Sendmail server, according to its version
number, does not properly identify the .\n string which identifies the
end of message text, which allows a remote attacker to cause a denial
of service or corrupt mailboxes via a message line that is 2047
characters long and ends in .\n.");
  script_set_attribute(attribute:"solution", value:
"Install Sendmail version 8.10.0 and higher, or install a vendor
supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2000-0319");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/04/24");
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

constraints = [{ "fixed_version" : "8.10.0" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
