#%NASL_MIN_LEVEL 70300
#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, touched up description (6/12/09)
# - Added patch date and updated URL (3/13/13)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10855);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0568");
  script_bugtraq_id(4290);

  script_name(english:"Oracle Application Server XSQLServlet XSQLConfig.xml Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"Sensitive data can be read on the remote host.");
  script_set_attribute(attribute:"description", value:
"It is possible to read the contents of the XSQLConfig.xml file which contains 
sensitive information.");
  # http://web.archive.org/web/20030405210233/http://www.nextgenss.com/papers/hpoas.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97653726");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/index.html");
  script_set_attribute(attribute:"solution", value:
"Move this file to a safer location and update your servlet engine's 
configuration file to reflect the change.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/02/06");
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

include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80, embedded:TRUE);



if(get_port_state(port))
{
 req = http_get(item:"/xsql/lib/XSQLConfig.xml",
 		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 tip = string("On a PRODUCTION system, under no circumstances should this confi
guration file reside in a directory that is browsable through the virtual path
 of your web server.");

if(tip >< r)
 {
 http_close_socket(soc);
 security_note(port);
 }
else
 {
 req = http_get(item:"/servlet/oracle.xml.xsql.XSQLServlet/xsql/lib/XSQLConfig.xml", port:port);
 soc = http_open_socket(port);
 if(soc)
  {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(tip >< r)	
 	security_note(port);

   }
  }
 }
}
