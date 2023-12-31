#
# (C) Tenable Network Security, Inc.
#

# 10/22/2003 updated by KK Liu 10/22/2003
# 	- check messenger service, if not on - exit
#	- check Windows OS
#

include("compat.inc");


if (description)
{
 script_id(11890);
 script_version("1.50");
 script_cvs_date("Date: 2019/03/06 18:38:55");

 script_cve_id("CVE-2003-0717");
 script_bugtraq_id(8826);
 script_xref(name:"MSFT", value:"MS03-043");
 script_xref(name:"MSKB", value:"828035");

 script_name(english:"MS03-043: Buffer Overrun in Messenger Service (828035) (uncredentialed check)");
 script_summary(english:"Checks for hotfix Q828035");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description",  value:
"A security vulnerability exists in the Messenger Service that could allow
arbitrary code execution on an affected system. An attacker who successfully
exploited this vulnerability could be able to run code with Local System
privileges on an affected system or could cause the Messenger Service to fail.
Disabling the Messenger Service will prevent the possibility of attack.

This plugin actually tests for the presence of this flaw." );
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2003/ms03-043");
 script_set_attribute( attribute:"solution",  value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/10/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/16");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2019 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_require_ports(135, 593);
 exit(0);
}

#
# The idea is to send a malformed message to the remote RPC
# messenger service.
# If the service is installed we receive an error message in return
# If the service is not installed, we receive a RPC unknown_if message
#
# Nothing gets printed on the remote screen.
#
# check messenger service, if not on - exit

debug = 0;
if ( TARGET_IS_IPV6 ) exit(0);

#if(!get_kb_item("SMB/messenger"))
#{
#	if (debug) display("Messenger Service disabled!\n");
#	exit(0);
#}

function dcom_recv(socket)
{
 local_var buf, len;

 buf = recv(socket:socket, length:9);
 if(strlen(buf) != 9)return NULL;

 len = ord(buf[8]);
 buf += recv(socket:socket, length:len - 9);
 return buf;
}

function check_win9xme(port)
{
	local_var chk, bindwinme, soc, rwinme, lenwinme, stubwinme, recv;
	chk[3] = raw_string (0x02,0x00,0x01,0x00);

	bindwinme = raw_string(
	0x05,0x00,0x0b,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x53,0x53,0x56,0x41,
	0xd0,0x16,0xd0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
	0xe6,0x73,0x0c,0xe6,0xf9,0x88,0xcf,0x11,0x9a,0xf1,0x00,0x20,0xaf,0x6e,0x72,0xf4,
	0x02,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,
	0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00
	);

    soc = open_sock_tcp(port);
	if(soc)
	{
	    send(socket:soc,data:bindwinme);
            rwinme  = dcom_recv(socket:soc);
            if(!strlen(rwinme))exit(0);
	    lenwinme = strlen(rwinme);
 	    if(lenwinme < 24 ) exit(0);
	    stubwinme = substr(rwinme, lenwinme-24, lenwinme-21);
	    if (debug)
	    {
	    	display('len = ', lenwinme, '\n');
			display('stub  = ', hexstr(stubwinme), '\n');
			display('r = ', hexstr(rwinme), '\n');
	    }
	    if (stubwinme >< chk[3])
	    {
	    	if (debug) display("Windows 95/98/ME not affected!\n");
			exit(0);
        }
	    close(soc);
	}
	else exit(0);
}


function check_XP(port)
{
	local_var bindxp, req, soc, recv, len;
	bindxp = raw_string(
	0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
	0xcc, 0x00, 0x00, 0x00, 0x84, 0x67, 0xbe, 0x18,
	0x31, 0x14, 0x5c, 0x16, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0xb8, 0x4a, 0x9f, 0x4d, 0x1c, 0x7d, 0xcf, 0x11,
	0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
	0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
	0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x01, 0x00, 0xa0, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
	0x0a, 0x42, 0x24, 0x0a, 0x00, 0x17, 0x21, 0x41,
	0x2e, 0x48, 0x01, 0x1d, 0x13, 0x0b, 0x04, 0x4d,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
	0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
	0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x01, 0x00, 0xb0, 0x01, 0x52, 0x97,
	0xca, 0x59, 0xcf, 0x11, 0xa8, 0xd5, 0x00, 0xa0,
	0xc9, 0x0d, 0x80, 0x51, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	0x02, 0x00, 0x00, 0x00 );


	req = raw_string (
	0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
	0xaa, 0x00, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41,
	0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x28, 0x63, 0x29, 0x20,
	0x75, 0x65, 0x72, 0x84, 0x20, 0x73, 0x73, 0x53,
	0x20, 0x82, 0x80, 0x67, 0x00, 0x00, 0x00, 0x00,
	0x80, 0x1d, 0x94, 0x5e, 0x96, 0xbf, 0xcd, 0x11,
	0xb5, 0x79, 0x08, 0x00, 0x2b, 0x30, 0xbf, 0xeb,
	0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
	0x5c, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x00, 0x00,
	0x41, 0x00, 0x41, 0x00, 0x5c, 0x00, 0x43, 0x00,
	0x24, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x2e, 0x00,
	0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
	0x58, 0x73, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x07, 0x00 );




    soc = open_sock_tcp(port);
	if(soc)
	{
	    send(socket:soc,data:bindxp);
        recv  = dcom_recv(socket:soc);
        if(!strlen(recv))exit(0);
	    send(socket:soc,data:req);
        recv  = dcom_recv(socket:soc);
        if(!strlen(recv))exit(0);

	    len = strlen(recv);
	    if (debug)
	    {
	    	display('len = ', len, '\n');
	    }
	    if (len == 32)
	    {
	    	if (debug) display("Windows XP found!\n");
	    	close(soc);
	    	return (1);
        }
	    close(soc);
	    return (0);
	}
	else exit(0);
}

function check_NT2K(port)
{
	local_var req, bindNT2K, soc, recv, len;
	bindNT2K = raw_string(
	0x05,0x00,0x0B,0x03,0x10,0x00,0x00,0x00,0x48,0x00,
	0x00,0x00,0x7F,0x00,0x00,0x00,0xD0,0x16,0xD0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,
	0x00,0x00,0x01,0x00,0x01,0x00,0xA0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,
	0x00,0x00,0x00,0x00,0x00,0x46,0x00,0x00,0x00,0x00,0x04,0x5D,0x88,0x8a,0xEB,0x1C,
	0xC9,0x11,0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60,0x02,0x00,0x00,0x00);


	req = raw_string (
	0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
	0xaa, 0x00, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41,
	0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x28, 0x63, 0x29, 0x20,
	0x75, 0x65, 0x72, 0x84, 0x20, 0x73, 0x73, 0x53,
	0x20, 0x82, 0x80, 0x67, 0x00, 0x00, 0x00, 0x00,
	0x80, 0x1d, 0x94, 0x5e, 0x96, 0xbf, 0xcd, 0x11,
	0xb5, 0x79, 0x08, 0x00, 0x2b, 0x30, 0xbf, 0xeb,
	0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
	0x5c, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x00, 0x00,
	0x41, 0x00, 0x41, 0x00, 0x5c, 0x00, 0x43, 0x00,
	0x24, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x2e, 0x00,
	0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
	0x58, 0x73, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x07, 0x00 );


    soc = open_sock_tcp(port);
	if(soc)
	{
	    send(socket:soc,data:bindNT2K);
        recv  = dcom_recv(socket:soc);
        if(!strlen(recv))exit(0);
	    send(socket:soc,data:req);
        recv  = dcom_recv(socket:soc);
        if(!strlen(recv))exit(0);

	    len = strlen(recv);
	    if (debug)
	    {
	    	display('len = ', len, '\n');
	    }
	    if (len == 32)
	    {
	    	if (debug) display("Windows NT found! Probe not available yet!\n");
	    	close(soc);
	    	#exit(0);
		return (1);
        }
        else
        {
 	    	if (debug) display("Windows 2000 found!\n");
        }
	    close(soc);
	    return (1);
	}
	else exit(0);
}

function check_winos()
{
	local_var port,soc;

	port = 135;
	if(!get_port_state(port))
	{
	 port = 593;
	 if ( ! get_port_state(port) ) exit(0);
	}
	else
	{
	 soc = open_sock_tcp(port);
	 if(!soc)
		{
		  if ( ! get_port_state(593) ) exit(0);
		  else port = 593;
		}
	 else close(soc);
	}

	check_win9xme(port:port);
	check_XP(port:port);
	check_NT2K(port:port);
}

function check_rpc_serv()
{
 local_var seq1, seq2, sport, req, ip, myudp, filter, i, rep, code, data;
seq1 = rand() % 256;
seq2 = rand() % 256;


sport = 2048 + rand() % 4096;

req = raw_string(0x04, 0x00, 0x28, 0x00, 0x10, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xf8, 0x91, 0x7b, 0x5a, 0x00, 0xff,
	0xd0, 0x11, 0xa9, 0xb2, 0x00, 0xc0, 0x4f, 0xb6,
	0xe6, 0xfc, 0x04, 0x00, seq1, seq2, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0c,
  	0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, seq1, seq2, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x34, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x00, 0x00, 0x00) + "TENABLE" +
    raw_string(0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x03, 0x00, 0x00, 0x00) + "tst" + raw_string(0) ;


ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0, ip_len:20, ip_id:rand(), ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP, ip_src:compat::this_host());

# The reply comes from a different port than port 135
myudp = forge_udp_packet(ip:ip, uh_sport:sport, uh_dport:135, uh_ulen: 8 + strlen(req), data:req);
filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip();

for(i=0;i<3;i++)
{
 rep = send_packet(myudp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
 if(rep)
 {
  sport = get_udp_element(udp:rep, element:"uh_sport");
  if ( sport == 135 ) exit(0);
  data = get_udp_element(udp:rep, element:"data");
  code = substr(data, strlen(data) - 4, strlen(data) - 1);
  if("f7060000" >< hexstr(code) ||
     "0300011c" >< hexstr(code)){ security_hole(port:135, proto:"udp"); exit(0);}
  break;
  }
 }
}

check_winos();
check_rpc_serv();
