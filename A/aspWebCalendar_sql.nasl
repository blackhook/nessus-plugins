#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14816);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-1552");
  script_bugtraq_id(11246);

  script_name(english:"aspWebCalendar calendar.asp SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a SQL injection attack.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running aspWebCalendar, an ASP script
designed to faciliate the integration of multiple calendars in a web-
based application.

There is a flaw in the remote software that could allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:full_revolution:aspwebcalendar");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/ASP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function check(port, req)
{
  local_var	r, ldata;
  ldata = "txtUserName=%27&txtPassword=&LoginButton=Login";
  r = http_send_recv3(port: port, method: 'POST', version: 11, item: req,
add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
	     data: ldata);
  if (isnull(r)) exit(0);

  if("error '80040e14'" >< r[2] && 
     "'Cal_User_UserName = ''''" >< r[2])
  	{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
  return(0);
}

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);
if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  if (is_cgi_installed3(item:dir + "/calendar.asp", port:port))
   check(port: port, req:dir + "/calendar.asp?action=processlogin");
 }
