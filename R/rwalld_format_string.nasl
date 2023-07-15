#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10950);
 script_version("1.27");
 script_cvs_date("Date: 2018/07/27 18:38:14");

 script_cve_id("CVE-2002-0573");
 script_bugtraq_id(4639);

 script_name(english:"Solaris rpc.rwalld Remote Format String Arbitrary Code Execution");
 script_summary(english:"Checks the presence of a RPC service");

 script_set_attribute(attribute:"synopsis", value:"An RPC service is running.");
 script_set_attribute(attribute:"description", value:
"The rpc.walld RPC service is running. Some versions of this server
allow an attacker to gain root access remotely, by consuming the
resources of the remote host then sending a specially formed packet
with format strings to this host.

Solaris 2.5.1, 2.6, 7, 8 and 9 are vulnerable to this issue. Other
operating systems might be affected as well.

Nessus did not check for this vulnerability, so this might be a false
positive.");
 script_set_attribute(attribute:"solution", value:"Deactivate this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/05/02");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"RPC");

 script_dependencie("os_fingerprint.nasl", "rpc_portmap.nasl");
 script_require_keys("rpc/portmap", "Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

os =  get_kb_item("Host/OS");
if ( os && egrep(pattern:"Solaris 1[0-9]", string:os)) exit(0);


#
# This is kinda lame but there's no way to remotely determine if
# this service is vulnerable to this flaw.
#
RPC_PROG = 100008;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_hole(port);
 else security_hole(port:port, protocol:"udp");
}
