#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26186);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"IBM Tivoli Storage Manager Client Acceptor Daemon Detection");

  script_set_attribute(attribute:"synopsis", value:
"A backup service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a Client Acceptor Daemon used by IBM Tivoli
Storage Manager Client for scheduling backups.");
  # https://www.ibm.com/developerworks/community/wikis/home?lang=en#!/wiki/Tivoli%20Storage%20Manager/page/PDF%20versions%20of%20the%20IBM%20Tivoli%20Storage%20Manager%20Version%205.5.x%20documentation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9855523");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1582);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(1582);
  if (!port) exit(0);
}
else port = 1582;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a startup message.
req = raw_string(
  0x00, 0x00, 0x08, 0xa5, 0x00, 0x01, 0x02, 0x00, 
  0x00, 0x00, 0x00, 0x1e, 0x00, 0x01, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);
send(socket:soc, data:req);
res = recv(socket:soc, length:64, min:0x2c);
close(soc);


# If...
if (
  # the response is long-enough and...
  strlen(res) >= 12 &&
  # it looks right and..
  raw_string(0x00, 0x00, 0x08, 0xa5, 0x00, 0x01, 0x03) == substr(res, 0, 6) &&
  # the byte at offset 11 is the packet length
  getbyte(blob:res, pos:11) == strlen(res)
)
{
  # Register and report the service.
  register_service(port:port, proto:"ibm_tsm_cad");
  security_note(port);
}
