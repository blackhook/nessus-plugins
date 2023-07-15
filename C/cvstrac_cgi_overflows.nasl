#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(14284);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");


 script_name(english:"CVSTrac cgi.c Multiple Overflows");
 script_summary(english:"Checks for CVSTrac version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by multiple remote overflows.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running cvstrac, a web-based bug and
patch-set tracking system for CVS.

This version contains multiple flaws in the mprintf, vmprintf, and 
vxprintf functions in cgi.c .  A remote attacker, exploiting this 
flaw, would be able to execute arbitrary code on the remote system.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of CVSTrac
***** installed there.");
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/chngview?cn=77");
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/chngview?cn=92");
 script_set_attribute(attribute:"solution", value:
"Update to version 1.1.4 or later as this reportedly fixes the issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/30");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("cvstrac_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80, embedded:TRUE);
kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];

if(ereg(pattern:"^(0\..*|1\.(0\.|1\.[0-3]([^0-9]|$)))", string:version)) security_hole(port);
