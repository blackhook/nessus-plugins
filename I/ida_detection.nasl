#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17258);
 script_version("1.16");
 script_cvs_date("Date: 2019/11/22");

 script_name(english:"IDA Pro Disassembler Software Detection");
 script_summary(english:"IDA Pro Detection");

 script_set_attribute(attribute:"synopsis", value:"The remote host is running a dissassembler program.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running the IDA Pro Disassembler
program.");
 script_set_attribute(attribute:"see_also", value:"http://www.datarescue.com/");
 script_set_attribute(attribute:"solution", value:"Check that this software fits with your corporate policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:datarescue:ida");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Service detection");
 script_require_udp_ports(23945);
 exit(0);
}

include("audit.inc");

port = 23945;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

req = raw_string(0x49,0x44,0x41,0x00,0x01,0x00,0x00,0x00) + crap(32);
match = raw_string(0x49,0x44,0x41,0x00,0x00);

send (socket:soc, data:req);
r = recv(socket:soc, length:40, timeout:3);
if ( ! r ) audit(AUDIT_RESP_NOT, port, 'a request', 'UDP', code:0);

if (match >< r)
	security_note(port:port, proto:"udp");
