#%NASL_MIN_LEVEL 70300
#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, description touch-up (6/9/09)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10850);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0562");
  script_bugtraq_id(4034);

  script_name(english:"Oracle 9iAS globals.jsa Database Credential Remote Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"Sensitive data may be disclosed on the remote host.");
  script_set_attribute(attribute:"description", value:
"In the default configuration of Oracle 9iAS, it is possible to make 
requests for the globals.jsa file for a given web application. 
These files should not be returned by the server as they often 
contain sensitive information such as database credentials.");
  # http://web.archive.org/web/20020212063119/http://www.nextgenss.com/advisories/orajsa.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1e12e40");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/index.html");
  script_set_attribute(attribute:"solution", value:
"Edit httpd.conf to disallow access to *.jsa.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/06");
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
# Make a request for one of the demo files .jsa files. This can be 
# improved to use the output of webmirror.nasl, allowing the plugin to
# test for this problem in configurations where the demo files have
# been removed.

 req = http_get(item:"/demo/ojspext/events/globals.jsa",
 		port:port); 
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("event:application_OnStart" >< r)	
 	security_warning(port);

 }
}
