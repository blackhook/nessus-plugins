#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15557);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-2180", "CVE-2004-2181");
  script_bugtraq_id(11429);

  script_name(english:"WowBB <= 1.61 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WowBB, a web-based forum written in PHP. 

According to its version, the remote installation of WowBB is 1.61 or
older.  Such versions are vulnerable to cross-site scripting and SQL
injection attacks.  A malicious user can steal users' cookies,
including authentication cookies, and manipulate SQL queries.");
  script_set_attribute(attribute:"see_also", value:"http://www.maxpatrol.com/advdetails.asp?id=7");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# the code!

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80, embedded:TRUE);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port))exit(0);

function check(req)
{
  local_var r;

  r = http_get_cache_ka(item:string(req, "/index.php"), port:port);
  if( r == NULL )exit(0);
  if(egrep(pattern:"WowBB Forums</TITLE>.*TITLE=.WowBB Forum Software.*>WowBB (0\..*|1\.([0-5][0-9]|60|61))</A>", string:r))
  {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
  }
}

if (thorough_tests) dirs = list_uniq(make_list("/forum", "/forums", "/board", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) check(req:dir);
