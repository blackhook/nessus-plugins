#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26024);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"PostgreSQL Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a PostgreSQL database server, or a derivative
such as EnterpriseDB.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("database_settings.nasl", "find_service2.nasl");
  script_require_ports("Services/unknown", 5432, 5444);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include('lists.inc');

port_list = make_list(5432, 5444);

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery"))
{
  unknown_list = get_unknown_svc_list();
  if (!isnull(unknown_list))
    port_list = collib::union(port_list, unknown_list);
}

db_port = get_kb_item('Database/Port');
if (!isnull(db_port))
  collib::push(db_port, list:port_list);

db_ports = get_kb_list('Database/*/Port');
if (!isnull(db_ports))
  port_list = collib::union(port_list, db_ports);

port_list = collib::remove_duplicates(port_list);

port = branch(port_list);

if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");


# Send a startup message.
#
# nb: see <http://developer.postgresql.org/pgdocs/postgres/protocol-message-formats.html>.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);
user = SCRIPT_NAME;
db = "nessus";

req = mkword(0x03) + mkword(0x00) +    # protocol version (3.0)
  "user" + mkbyte(0) +
    user + mkbyte(0) +
  "database" + mkbyte(0) +
    db + mkbyte(0) +
  "client_encoding" + mkbyte(0) +
    "UNICODE" + mkbyte(0) +
  "DateStyle" + mkbyte(0) +
    "ISO" + mkbyte(0) +
  mkbyte(0);
req =
  mkdword(strlen(req)+4) +
  req;
send(socket:soc, data:req);
res = recv(socket:soc, length:1, min:1);
if ( ! res || res[0] !~ "(E|R)" ) exit(0);
res += recv(socket:soc, length:4, min:4);
if ( strlen(res) < 5 ) exit(0);
len = getdword(blob:res, pos:1);
if ( len > 2048 ) exit(0);
res += recv(socket:soc, length:len - 4);

# If...
if (
  strlen(res) >= 5 &&
  # either the response is ...
  (
    # an error or...
    (
      res[0] == "E" &&
      (
        "SERROR" >< res ||
        "SFATAL" >< res ||
        "SPANIC" >< res
      )
    ) ||
    # an authentication request
    (
      res[0] == "R" &&
      (
        getdword(blob:res, pos:1) == 8 ||
        getdword(blob:res, pos:1) == 10 ||
        getdword(blob:res, pos:1) == 12 ||
        (getdword(blob:res, pos:1) == 23 && strlen(res) >= 24 &&
         substr(res, 9, 21) == "SCRAM-SHA-256")
      )
    )
  )
)
{
  if (get_kb_item("Settings/PCI_DSS") && res[0] == "R")
  {
    set_kb_item(name:"PCI/ClearTextCreds/" + port, value:"The remote Postgresql server accepts cleartext logins.");
  }

  # Register and report the service.
  register_service(port:port, proto:"postgresql");
  security_note(port);

  app = "PostgreSQL";
  version = UNKNOWN_VER;
  service = "postgresql";
  cpe = "cpe:/a:postgresql:postgresql";

  register_install(
    vendor   : "PostgreSQL",
    product  : "PostgreSQL",
    app_name : app,
    version  : version,
    port     : port,
    service  : service,
    cpe      : cpe
  );
}
else exit(0, "The response from the service listening on port "+port+" does not look like PostgreSQL.");
