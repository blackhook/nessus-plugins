#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2019/04/16.

include("compat.inc");


if (description)
{
 script_id(10031);
 script_version("1.31");
 script_cvs_date("Date: 2019/04/16 15:29:03");


 script_name(english:"RPC bootparamd Service Information Disclosure (Deprecated)");
 script_summary(english:"Checks the presence of a RPC service");

 script_set_attribute(attribute:"synopsis",  value:
"This plugin has been deprecated.");
 script_set_attribute( attribute:"description", value:
"The bootparamd RPC service is running.  It is used by diskless clients
to get the necessary information needed to boot properly.

If an attacker uses the BOOTPARAMPROC_WHOAMI and provides the correct
address of the client, then he will get its NIS domain back from
the server. Once the attacker discovers the NIS domain name, he may
easily get your NIS password file.");
 script_set_attribute( attribute:"solution", value:
"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"1991/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/30");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"RPC");
 script_copyright(english:"This script is Copyright (C) 1999-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

exit(0, "This plugin is deprecated");
#
# The script code starts here
#

include("misc_func.inc");
include("sunrpc_func.inc");

RPC_PROG = 100026;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 set_kb_item(name:"rpc/bootparamd", value:TRUE);
 if(tcp)security_warning(port);
 else security_warning(port:port, protocol:"udp");
}
