#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16200);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-1315");
  script_bugtraq_id(10701);
  script_xref(name:"CERT", value:"497400");
  script_xref(name:"EDB-ID", value:"647");

  script_name(english:"phpBB < 2.0.11 Multiple Vulnerabilities (ESMARKCONANT)");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB older than 2.0.11. It is
reported that this version of phpBB is susceptible to a script
injection vulnerability which may allow an attacker to execute
arbitrary code on the remote host. In addition, phpBB has been
reported to multiple SQL injections, although Nessus has not checked
for them.

ESMARKCONANT is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB 2.0.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"metasploit_name", value:'phpBB viewtopic.php Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpbb_group:phpbb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("phpbb_detect.nasl");
  script_require_keys("www/phpBB");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

version = matches[1];
if ( ereg(pattern:"^([01]\..*|2\.0\.([0-9]|1[01])[^0-9])", string:version))
	security_hole(port);

