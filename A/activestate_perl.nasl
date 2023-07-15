#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(11007);
 script_version("1.25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");


 script_name(english:"ActivePerl findtar Sample Script Remote Command Execution");
 script_summary(english:"Determines if ActivePerl is vulnerable");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a scripting language that is affected by a
remote command execution flaw.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of ActiveState Perl which is
affected by a remote command execution flaw.  An attacker could exploit
this flaw in order to execute arbitrary commands in the context of the
affected application.");

 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Dec/119");
 script_set_attribute(attribute:"solution", value:
"Upgrading to version 5.6.3 or newer reportedly fixes the
vulnerability.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/08");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2002-2021 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/iis");
 exit(0);
}


#
# The code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

b = get_http_banner(port: port);
if ( "IIS" >!< b ) exit(0, "The web server on port "+port+" is not IIS.");

w = http_send_recv3(method:"GET", port:port, item:'/."./."./winnt/win.ini%20.pl', exit_on_fail: 1);
r = strcat(r[0], r[1], '\r\n', r[2]);
if("Semicolon seems to be missing at" >< r)
{
 security_hole(port);
}
