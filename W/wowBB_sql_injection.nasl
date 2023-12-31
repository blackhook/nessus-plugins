#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18221);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-1554");
  script_bugtraq_id(13569);

  script_name(english:"WowBB view_user.php Multiple Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection flaw.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WowBB, a web-based forum written in PHP. 

The remote version of this software is vulnerable to SQL injection
attacks through the script 'view_user.php'.  A malicious user can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, attacks against the underlying
database, and the like.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/399637");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

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

global_var	port;

function check(req)
{
  local_var buf, r;

  buf = http_get(item:string(req,"/view_user.php?list=1&letter=&sort_by='select"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if ("Invalid SQL query: SELECT" >< r && 'TITLE="WowBB Forum Software' >< r)
  {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
  }
}

port = get_http_port(default:80, embedded:TRUE);
if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port))exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/forum", "/forums", "/board", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir ( dirs ) check(req:dir);
