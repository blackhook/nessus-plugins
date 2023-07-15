#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(22270);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Zend Session Clustering Daemon Detection");

  script_set_attribute(attribute:"synopsis", value:
"A Zend Session Clustering daemon is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Zend Session Clustering daemon, a
component of the Zend Platform used to synchronize session data across
a cluster of PHP servers.");
  # http://web.archive.org/web/20061105143529/http://www.zend.com/products/zend_platform/in_depth
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e6a67b9");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zend:zend_framework");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 34567);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(34567);
  if (!port) exit(0);
}
else port = 34567;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a request.
req = "TEN@ABLEBLE";
send(socket:soc, data:req);
res = recv(socket:soc, length:128);
close(soc);


# If ...
if (
  # response is 20 chars long and...
  strlen(res) == 20 &&
  # it looks right.
  substr(res, 0, 6) == "TENABLE"
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"zend_scd");
  security_note(port);
}
