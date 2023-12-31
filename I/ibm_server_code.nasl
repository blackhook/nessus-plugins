#%NASL_MIN_LEVEL 70300
#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# v. 1.00 (last update 08.11.01)
#
# Changes by Tenable:
# - Revised plugin title, CVSS2 score (1/08/2009)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10799);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(3518);

  script_name(english:"IBM HTTP Server on AS/400 Trailing Slash Source Code Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"IBM's HTTP Server on the AS/400 platform is vulnerable to an attack
that will show the source code of the page -- such as a .html or 
.jsp page -- by attaching an '/' to the end of a URL.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Nov/29");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2001/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2001-2022 Felix Huber");

  script_dependencies("httpver.nasl", "http_version.nasl", "webmirror.nasl");
  script_require_keys("www/ibm-http");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);


dir[0] = "/index.html";
dir[1] = "/index.htm";
dir[2] = "/index.jsp";
dir[3] = "/default.html";
dir[4] = "/default.htm";
dir[5] = "/default.jsp";
dir[6] = "/home.html";
dir[7] = "/home.htm";
dir[8] = "/home.jsp";


files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(!isnull(files))
{
 files = make_list(files);
 if(files[0])dir[9] = files[0];
}

if(get_port_state(port))
{

 for (i = 0; dir[i] ; i = i + 1)
 {
    
	req = http_get(item:string(dir[i], "/"), port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if(r == NULL)exit(0);
	if("Content-Type: www/unknown" >< r)
	    {
                    	security_warning(port);
                     	exit(0);
	    }

  }
}

