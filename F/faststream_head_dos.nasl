#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15764);
 script_version("1.14");

 script_cve_id("CVE-2004-2534");
 script_bugtraq_id(11687);
 
 script_name(english:"Fastream NETFile FTP/Web Server HEAD Request Saturation DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running FastStream NETFile Server
version 7.1 or older.  These versions do not close the connection when
an HTTP HEAD request is received with the keep-alive option set.  An
attacker may exploit this flaw by sending multiple HEAD requests to
the remote host, thus consuming all its file descriptors until it does
not accept connections any more." );
 script_set_attribute(attribute:"see_also", value:"http://users.pandora.be/bratax/advisories/b003.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.1.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/15");
 script_cvs_date("Date: 2018/07/11 17:09:26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks version of FastStream NetFile");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie( "http_version.nasl" );
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
if(!banner)exit(0);

if ( egrep(pattern:"^Server: Fastream NETFile Web Server ([0-6]\..*)", string:banner) ) 
	security_warning(port);
