#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10687);
 script_version ("1.25");
 script_cvs_date("Date: 2018/12/21 16:12:09");
 
 script_name(english: "Web Server HTTP POST Method Handling Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be vulnerable to a handling overflow denial of service attack." );
 script_set_attribute(attribute:"description", value:
"Nessus tests the stability of a remote web service by sending a 
significantly large HTTP POST and then confirms if the web service is
still responsive." );
 script_set_attribute(attribute:"solution", value: "Consult your vendor for a patch or workaround.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"CVE not assigned. Assigning a typical DoS score.");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/06/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Web server buffer overflow");
 script_category(ACT_DENIAL);
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus 
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 
 script_copyright(english: "This script is Copyright (C) 2001-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);
if (http_is_dead(port:port))exit(1, "The web server on port "+port+" is already dead.");

r = http_send_recv3(port: port, method: 'POST', item: "/"+crap(4096), exit_on_fail: 0);

if ( service_is_dead(port:port, exit: 0) > 0 || 
     (report_paranoia >= 2 && http_is_dead(port: port, retry: 3)) )
{
	security_hole(port);
	set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
