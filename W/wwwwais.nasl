#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(10597);
 script_version("1.38");
 script_cve_id("CVE-2001-0223");
 script_bugtraq_id(2292);

 script_name(english:"wwwwais QUERY_STRING Parameter Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The 'wwwwais' CGI is installed.  This CGI has a well known security
flaw that lets an attacker execute arbitrary commands with the
privileges of the http daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=97984174724339&w=2" );
 script_set_attribute(attribute:"solution", value:
"Remove the script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/01/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/wwwwais");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2001-2021 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 r = http_send_recv3(method: "GET", port: port, item: strcat(dir, "/wwwwais?version=123&", crap(4096)), exit_on_fail: 1);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if("memory violation" >< buf)
 {
   security_hole(port);
   exit(0);
 }
}

