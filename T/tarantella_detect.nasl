#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(22478);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Sun Secure Global Software / Tarantella Detection");

  script_set_attribute(attribute:"synopsis", value:
"Sun Secure Global Software / Tarantella is installed on the remote
host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Sun Secure Global Software or Tarantella, a
Java-based program for web-enabling applications running on a variety
of platforms.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/sun/index.html");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tarantella:tarantella_enterprise");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("soap_detect.nasl");
  script_require_ports("Services/soap_http", 3144);

  exit(0);
}


include("byte_func.inc");


port = get_kb_item("Services/soap_http");
if (!port) port = 3144;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# First, establish a connection.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
loc = "tarantella";
host = "nessus";
ip = compat::this_host();
req = 
  "WAIP" +
  mkbyte(1) +
  mkword(strlen(loc+host+ip)+12+6) + 
  raw_string(
    0x05, 0x00, 0x61, 0x00, 0x48, 0x0c, 0x18, 0x00, 
    0x18, 0x00, 0x50, 0x00
  ) +
  mkword(strlen(loc)) + loc +
  mkword(strlen(host)) + host +
  mkword(strlen(ip)) + ip;
send(socket:soc, data:req);

res = recv(socket:soc, length:16);
if (strlen(res) != 11) exit(0);
if (hexstr(res) != "010800000000000f000000") exit(0);


# Now, try to authenticate.
user = "nessus";
pass = raw_string(0x04, 0x04, 0x05, 0x12, 0x5b, 0x1f);     # encrypted, perhaps?
req = 
  raw_string(0x02, 0x0f, 0x00, 0x00) +
  mkword(strlen(user)) + user +
  mkword(strlen(pass)) + pass;
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);


# It's Tarantella if...
if (
  # the word at the first byte is the packet length and...
  (strlen(res) > 3 && getword(blob:res, pos:1) == strlen(res) - 3) &&
  # authentication...
  (
    # failed or...
    hexstr(res) == "020600020000000000" ||
    # was successful
    getbyte(blob:res, pos:0) == 5
  )
) security_note(port);
