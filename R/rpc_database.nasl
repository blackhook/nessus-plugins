#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10214);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVA", value:"0001-A-0588");

 script_name(english:"RPC database Service Detection");
 script_summary(english:"checks the presence of a RPC service");

 script_set_attribute(attribute:"synopsis", value:"A deprecated RPC service is running.");
 script_set_attribute(attribute:"description", value:
"The database RPC service is running. If you do not use this service,
then you should disable it as it may become a security threat in the
future, if a vulnerability is discovered.");
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it, or filter incoming traffic
to this port");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/19");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2020 Tenable Network Security, Inc.");
 script_family(english:"RPC");

 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap", "Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("misc_func.inc");
include('global_settings.inc');
include("sunrpc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);



RPC_PROG = 100016;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_note(port);
 else security_note(port:port, protocol:"udp");
}
