#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# this plugin is broken (no further info)
exit(0);

if(description)
{
 script_id(15516);
 script_version("1.11");
 script_cve_id("CVE-2004-1603");
 script_bugtraq_id(11449);

 script_name(english:"cPanel Backup File Local Disclosure");
 
 desc["english"] = '
The remote host is running a version of cpanel which is older or as
old as version 9.4.1.

The remote version of this software is vulnerable to a
file disclosure flaw in the Remote Backup module which may
allow a local attacker to read arbitrary files on the remote system.

Solution : Upgrade to the newest version of cPanel or disable this service
Risk factor : Medium';


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of cpanel";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 2082);
 exit(0);
}

# Check starts here

exit(0); # Broken
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:2082, embedded:TRUE);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( ! banner )exit(0);
if ( egrep(pattern:"^Server: cpsrvd/([0-8]\.|9\.([0-3]\.|4\.[01][^0-9]))", string:banner) ) security_warning(port);
