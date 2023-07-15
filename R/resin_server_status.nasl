#%NASL_MIN_LEVEL 70300
#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

# Changes by Tenable:
# - Revised plugin title, family change (4/2/2009)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11930);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Resin Status Page Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue.");
  script_set_attribute(attribute:"description", value:
"Requesting the URI '/caucho-status' or '/server-status' gives
information about the currently running Resin java servlet container.");
  script_set_attribute(attribute:"solution", value:
"If you don't use this feature, set the content of the
'<caucho-status>' element to 'false' in the resin.conf file.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/11/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:caucho:resin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2003-2022 StrongHoldNet");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);
if(!get_port_state(port))exit(0);

caucho_status[0] = "/caucho-status";
caucho_status[1] = "/server-status";

foreach page (caucho_status) {
  req = http_get(item:page, port:port);
  r = http_keepalive_send_recv(port:port, data:req);

  if(r && "<title>Status : Caucho Servlet Engine" >< r) {
    report = string(
      "\n",
      "The status page is available via the following URI :\n",
      "\n",
      "  ", page, "\n"
    );
    security_warning(port:port, extra:report);
    exit(0);
  }
}

