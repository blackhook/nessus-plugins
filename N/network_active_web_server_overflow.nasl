#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15421);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(11326);

  script_name(english:"NetworkActiv Web Server Encoded URL Request Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service.");
  script_set_attribute(attribute:"description", value:
"The remote host is running NetworkActive Web Server - an alternative web server.

There is a vulnerability in the remote version of this software that 
could allow an attacker to cause a denial of service against the 
remote server by sending an HTTP GET request containing a '%25' 
character.");
  script_set_attribute(attribute:"see_also", value:"http://www.networkactiv.com/WebServer.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NetworkActive Web Server version 2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:networkactiv:networkactiv_web_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if (! banner) exit(1, "No HTTP banner on port "+port);

if ( egrep(pattern:"^Server: NetworkActiv-Web-Server/(0\.[0-9]|1\.0[^0-9])", string:banner) )
 {
   security_warning(port);
 }
