#%NASL_MIN_LEVEL 70300
# By John Lampe ... j_lampe@bellsouth.net
#
# changes by rd: code of the plugin checks for a valid tag in the reply

# Changes by Tenable:
# - Revised plugin title (4/7/2009)
# - Updated to use compat.inc (11/20/2009)
# - Fixing typo, clean up code (06/07/2022)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11657);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/09");

  script_name(english:"Synchrologic Email Accelerator aggregate.asp User Account Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an information disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host seems to be running Synchrologic Email Accelerator Synchrologic is a product which allows remote PDA 
users to sync with email, calendar, etc.

If this server is on an Internet segment (as opposed to internal), you may wish to tighten the access to the 
aggregate.asp page.

The server allows anonymous users to look at Top Network user IDs Example : http://IP_ADDRESS/en/admin/aggregate.asp");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
   script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Information Disclosure");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:articatech:artica");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_keys("www/ASP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http_func.inc');
include('http_keepalive.inc');

var port = get_http_port(default:80, embedded:TRUE);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

var req = http_get(item:"/en/admin/aggregate.asp", port:port);
var res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if("/css/rsg_admin_nav.css" >< res)
	security_warning(port);
