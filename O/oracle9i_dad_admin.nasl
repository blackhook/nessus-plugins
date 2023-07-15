#%NASL_MIN_LEVEL 70300
#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10849);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-1235");
  script_bugtraq_id(2150);

  script_name(english:"Oracle 9iAS mod_plsql DAD Admin Interface Access");

  script_set_attribute(attribute:"synopsis", value:
"Sensitive resources can be accessed.");
  script_set_attribute(attribute:"description", value:
"In a default installation of Oracle 9iAS, it is possible to access the 
mod_plsql DAD Admin interface. Access to these pages should be restricted.");
  script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/1/155881");
  script_set_attribute(attribute:"solution", value:
"Edit the wdbsvr.app file, and change the setting 'administrators=' to 
named users who are allowed admin privileges.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
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

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80, embedded:TRUE);

if(get_port_state(port))
{ 
# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/portal30/admin_/", port:port);	      
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Gateway Configuration Menu" >< r)	
 	security_warning(port);

 }
}
