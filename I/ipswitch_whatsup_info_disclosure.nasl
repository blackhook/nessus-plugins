#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(21562);
 script_version("1.25");

 script_cve_id("CVE-2006-2351", "CVE-2006-2352", "CVE-2006-2353", "CVE-2006-2354", "CVE-2006-2355", "CVE-2006-2356", "CVE-2006-2357");
 script_bugtraq_id(17964);

 script_name(english:"Ipswitch WhatsUp Professional Multiple Vulnerabilities (XSS, Enum, ID)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Ipswitch WhatsUp Professional,
which is used to monitor states of applications, services and hosts. 

The version of WhatsUp Professional installed on the remote host is
prone to multiple issues, including source code disclosure and
cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/433808/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/products/whatsup/professional/" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:whatsup");
 script_end_attributes();
 
 script_summary(english:"Checks for Ipswitch WhatsUp Professional Information Disclosure");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8022);
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8022, embedded:TRUE);
if (!get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ("Server: Ipswitch" >!< banner) exit(0);

req = http_get(item:"/NmConsole/Login.asp.", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( r == NULL )exit(0);

if (
  'SOFTWARE\\\\Ipswitch\\\\Network Monitor\\\\WhatsUp' >< r &&
  (
    '<%= app.GetDialogHeader("Log In") %>' >< r ||
    egrep(pattern:'<%( +if|@ +LANGUAGE="JSCRIPT")', string:r)
  )
) {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
