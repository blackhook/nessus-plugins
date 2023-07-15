#%NASL_MIN_LEVEL 70300
# 
# (C) Nicolas Gregoire <ngregoire@exaprobe.com>
#
# Rewritten by Tenable Network Security
#

# Changes by Tenable:
# - Revised plugin title, changed family (6/1/09)


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(15910);
 script_version("1.24");
 script_cve_id("CVE-2004-1133", "CVE-2004-1134");
 script_bugtraq_id(11820);

 script_name(english:"Microsoft W3Who ISAPI w3who.dll Multiple Remote Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The Windows 2000 Resource Kit ships with a DLL that displays the browser 
client context. It lists security identifiers, privileges and $ENV variables. 

Nessus has determined that this file is installed on the remote host.

The w3who.dll ISAPI may allow an attacker to execute arbitrary commands 
on this host, through a buffer overflow, or to mount cross-site 
scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2004/Dec/174");
 script_set_attribute(attribute:"solution", value:
"Delete this file." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft IIS ISAPI w3who.dll Query String Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/06");

 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Determines the presence of w3who.dll");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2021 Nicolas Gregoire <ngregoire@exaprobe.com>");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

req  = http_get(item:"/scripts/w3who.dll", port:port);
res  = http_keepalive_send_recv(port:port, data:req);

if ("Access Token" >< res && "Environment variables" >< res)
{
 req  = http_get(item:"/scripts/w3who.dll?bogus=<script>alert('Hello')</script>", port:port);
 res  = http_keepalive_send_recv(port:port, data:req);

 if ("<script>alert('Hello')</script>" >< res)
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
