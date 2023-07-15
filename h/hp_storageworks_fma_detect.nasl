#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52654);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"HP StorageWorks File Migration Agent Detection");

  script_set_attribute(attribute:"synopsis", value:
"An HP StorageWorks File Migration Agent is listening on the remote
host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an HP StorageWorks File Migration Agent,
which migrates rarely used files to external hosts, recalling them as
needed.");
  # http://h10010.www1.hp.com/wwpc/ca/en/sm/WF05a/12135568-12135570-12135570-12197452-12197452-12298394.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8c0f313");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:storageworks");
  script_set_attribute(attribute:"hardware_inventory", value:"true");
  script_set_attribute(attribute:"os_identification", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 9111);

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(9111);
  if (!port) exit(0, "There are no unknown services.");
}
else port = 9111;

if (known_service(port:port)) exit(0, "The service on port "+port+" has already been identified.");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");

# All parameters in this protocol are little-endian.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# Send a hand-crafted FMA archive information request.
req = "_RRP" + raw_string(
  0x00, 0x01, 0x00, 0x00, 0x11, 0x00, 0x02, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);

sock = open_sock_tcp(port);
if (!sock) exit(1, "Failed to open a socket on port "+port+".");

# Probe the service.
send(socket:sock, data:req);
res = recv(socket:sock, length:24, min:24);
close(sock);
if (strlen(res) == 0) exit(0, "The service on port "+port+" failed to respond.");

# Check if it's an FMA response.
if (strlen(res) < 4 || substr(res, 0, 3) != "_RRP")
  exit(0, "An HP StorageWorks File Migration Agent is not running on port " + port + " .");

register_service(port:port, ipproto:"tcp", proto:"hp_storageworks_fma");
security_note(port);
