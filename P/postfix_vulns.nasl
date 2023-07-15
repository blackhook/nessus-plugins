#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11820);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-0468", "CVE-2003-0540");
  script_bugtraq_id(8361, 8362);
  script_xref(name:"RHSA", value:"2003:251-01");
  script_xref(name:"SuSE", value:"SUSE-SA:2003:033");

  script_name(english:"Postfix < 2.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Postfix that is as old as or 
older than 1.1.12.

There are two vulnerabilities in this version that could allow an 
attacker to remotely disable it, or to be used as a DDoS agent against 
arbitrary hosts.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Postfix 2.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0468");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/08/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postfix:postfix");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpscan.nasl", "smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_kb_item("smtp/" + port + "/real_banner");

if(!banner) banner = get_kb_item_or_exit("smtp/" + port + "/banner");

if(preg(pattern:".*Postfix 1\.(0\..*|1\.([0-9][^0-9]|1[0-2]))", string:banner)||
   preg(pattern:".*Postfix 2001.*", string:banner))
{
 security_warning(port);
}
