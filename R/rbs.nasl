#%NASL_MIN_LEVEL 70300
#
# This script was written by Zorgon <zorgon@linuxstart.com>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title (1/05/2009)


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(10521);
 script_version("1.30");

 script_cve_id("CVE-2000-1036");
 script_bugtraq_id(1704);
 
 script_name(english:"Extent RBS Web Server Image Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The version of Extent RBS ISP installed on the remote host fails to
sanitize input to the 'Image' parameter of the 'Newuser' script.  An
unauthenticated, remote attacker can leverage this to read arbitrary
files on the affected host with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Sep/387" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/09/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the presence of Extent RBS ISP 2.5";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2021 Zorgon <zorgon@linuxstart.com>");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80, embedded:TRUE);

res = is_cgi_installed_ka(port:port, item:"/newuser");
if(res){
 req = string("/newuser?Image=../../database/rbsserv.mdb");
 req = http_get(item:req, port:port);
 soc = http_open_socket(port);
 if ( ! soc ) exit(1, "Could not open a connection to the remote host on port " + port);
 send(socket:soc, data:req);
 buf = http_recv(socket:soc);
 http_close_socket(soc);
 if("SystemErrorsPerHour" >< buf)	
 	security_warning(port);
}
