#%NASL_MIN_LEVEL 70300
#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (6/10/09)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10852);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0565");
  script_bugtraq_id(4034);

  script_name(english:"Oracle 9iAS _pages Directory Compiled JSP Source Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"Sensitive data may be read on the remote host.");
  script_set_attribute(attribute:"description", value:
"In a default installation of Oracle 9iAS it is possible to read the 
source of JSP files. When a JSP is requested it is compiled 'on the fly'
and the resulting HTML page is returned to the user. Oracle 9iAS uses a
folder to hold the intermediate files during compilation. These files 
are created in the same folder in which the .JSP page resides. Hence, it
is possible to access the .java and compiled .class files for a given 
JSP page.");
  # http://web.archive.org/web/20030407050036/http://otn.oracle.com/deploy/security/pdf/ias_modplsql_alert.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80fe4531");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/index.html");
  script_set_attribute(attribute:"solution", value:
"Edit httpd.conf to disallow access to the _pages folder.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server_web_cache");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Matt Moore");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/OracleApache");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here

include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80, embedded:TRUE);

if(get_port_state(port))
{
# This plugin uses a demo jsp to test for this vulnerability. It would be 
# better to use the output of webmirror.nasl to find valid .jsp pages
# which could then be used in the test. In situations where the demo pages
# have been removed this plugin will false negative.
 
 req = http_get(item:"/demo/ojspext/events/index.jsp", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("This page has been accessed" >< r)	
	req = http_get(item:"/demo/ojspext/events/_pages/_demo/_ojspext/_events/_index.java", port:port);
	soc = http_open_socket(port);
	if(soc)
	{
	send(socket:soc, data:req);
	r = http_recv(socket:soc);
	http_close_socket(soc);
	
	if("import oracle.jsp.runtime.*" >< r)security_warning(port);
  }
 }
}
