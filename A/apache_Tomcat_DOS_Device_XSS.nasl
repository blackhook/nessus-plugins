#%NASL_MIN_LEVEL 70300
#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#      Also covers BugtraqID: 5193 (same Advisory ID#: wp-02-0008)
#
# See the Nessus Scripts License for details
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11042);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(5194);

  script_name(english:"Apache Tomcat DOS Device Name XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting issue.");
  script_set_attribute(attribute:"description", value:
"Apache Tomcat is the servlet container that is used in the official
Reference Implementation for the Java Servlet and JavaServer Pages
technologies. 

By making requests for DOS Device names it is possible to cause Tomcat
to throw an exception, allowing cross-site scripting attacks.  The 
exception also reveals the physical path of the Tomcat installation.");
  script_set_attribute(attribute:"see_also", value:"https://www.westpoint.ltd.uk/advisories/wp-02-0008.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat v4.1.3 beta or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/07/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Matt Moore");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_keys("www/tomcat");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

# Check starts here
include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:8080, embedded:TRUE);
if (!port) exit(0, "No web servers were found");

if(!get_port_state(port)) exit(0, "Port "+port+" is not open.");
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0, "The web server listening on port "+port+" is affected by a generic XSS vulnerability.");

banner = get_http_banner(port:port);
if (!banner) exit(1, "Failed to get the banner from the web server listening on port "+port+".");
if ("Tomcat" >!< banner && "Apache-Coyote" >!< banner)
  exit (0, "The web server listening on port "+port+" is not Tomcat.");

if (!egrep(pattern:"^Server: .*Tomcat/([0-3]\.|4\.0|4\.1\.[0-2][^0-9])", string:banner) ) exit(0, "The version of Tomcat listening on port "+port+" is not affected.");

req = http_get(item:"/COM2.<IMG%20SRC='JavaScript:alert(document.domain)'>", port:port);
soc = http_open_socket(port);
if(soc)
{ 
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 confirmed = string("JavaScript:alert(document.domain)"); 
 confirmed_too = string("java.io.FileNotFoundException");
 if ((confirmed >< r) && (confirmed_too >< r)) 	
	{
 		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
                exit(0);
	}
}
exit(0, "The web server listening on port "+port+" is not affected.");
