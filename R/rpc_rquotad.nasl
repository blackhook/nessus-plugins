#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10226);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

 script_cve_id("CVE-1999-0625");

  script_xref(name:"IAVA", value:"0001-A-0590");

 script_name(english:"rquotad Service Detection");
 script_summary(english:"checks the presence of a RPC service");

 script_set_attribute(attribute:"synopsis", value:"A deprecated RPC service is running.");
 script_set_attribute(attribute:"description", value:
"The rquotad RPC service is running.  If you do not use this service,
then disable it as it may become a security threat in the future, if a
vulnerability were to be discovered.");
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it, or filter incoming traffic
to this port");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0625");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2020 Tenable Network Security, Inc.");
 script_family(english:"RPC");
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}


#
# The script code starts here
#

include("misc_func.inc");
include('global_settings.inc');
include("sunrpc_func.inc");

if ( report_paranoia < 2 && ! get_kb_item("Settings/PCI_DSS")) exit(0);




RPC_PROG = 100011;
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
