#%NASL_MIN_LEVEL 70300

# This script was written by Laurent Kitzinger <lkitzinger@yahoo.fr>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/28/09)

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(10616);
 script_version("1.30");
 script_cve_id("CVE-2001-0211");
 script_bugtraq_id(2362);
 
 script_name(english:"WebSPIRS webspirs.cgi Traversal Arbitrary File Access");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to
information disclosure." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WebSPIRS, SilverPlatter's Information
Retrieval System for the web. 

The installed version of WebSPIRS has a well-known security flaw that
lets an attacker read arbitrary files with the privileges of the http
daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Feb/61");
 script_set_attribute(attribute:"solution", value:
"Remove this CGI script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of webspirs.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2021 Laurent Kitzinger");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("data_protection.inc");

port = get_http_port(default:80, embedded:TRUE);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:string(dir, "/webspirs.cgi?sp.nextform=../../../../../../../../../etc/passwd"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL ) exit(0);		
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r)) {
    r = data_protection::redact_etc_passwd(output:r);
    if (report_verbosity > 0) {
      report = string("\n", r, "\n");
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
 }
}
