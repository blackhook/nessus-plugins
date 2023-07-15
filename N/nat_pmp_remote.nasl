#TRUSTED 1551b39f1af9c8b9b3d79edd755311f949140a47b176f5d43d87d9854de2fa349424f1038f7606c46d1a5bb5cf30fc13bf2791326b5781b94ea1ea9fd704e5dbd0e2a0ab1fa1e2d66eba65baf648bef0a88d5b2cbc8e64285b485453116618876370a9ee80972800c144be0abc994e6192d95673cef77c7db8ee487ebf4d542a7329534eda4c1001efb35f008277a7578635105ea7e6a3c503fa7ecb33c071a5ef664e3739615d99ffaf038bc591128b15f3145297a874cf1b2da4f5f3f0726fd451536d5ab04cd4f03d095ce2e1310590340897d21cdefb63232f9e242cb09ebe40354d3be3d6e42fb9d2f006e0f333c44362910106ff67749d4a51b32e2d48ae3adba9809f0e7abc3c156e1505a26a41fa11f3f268d9de5a27e446b79e1aa4772498121d29786e252976bdd03221f11077cdf3e1525d589e84f617561ed8d249bb93c13c09934e511945546792e41befeba6aa7d8d21b340d78ff66f9069d806dbce6ca12336ca3116a8908bfdf86181cd21a8eae58a3c9e0bc05d131e357d905a30d7f16ad8cb29ffd20edcf8e96bd11efd55e5737a65828a32ced475c6bc66d7016ae22fe085abcd4bee67f0248fc3d7d9bf9643bff2b81e6803d060166d142291faf606ff19d62b0e55dd718c9c2587f6b5fb4e62748604ecb40ad772c66f6ad7ac5dbd2be52fbf20e7157d5f7804620eb8008d6a7727c642910c84b195
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(73124);
 script_version("1.5");
 script_set_attribute(attribute:"plugin_modification_date", value:"2019/03/06");

 script_xref(name:"CERT", value:"184540");

 script_name(english:"NAT-PMP Detection (remote network)");
 script_summary(english:"NAT-PMP detection.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to obtain information about the remote network.");
 script_set_attribute(attribute:"description", value:
"The remote device has the NAT-PMP protocol enabled. This protocol
may allow any application on an internal subnet to request port
mappings from the outside to the inside.

If this service is reachable from the outside your network, it may
allow a remote attacker to gain more information about your network
and possibly to break into it by creating dynamic port mappings.");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to UDP port 5351.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

 script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2014-2019 Tenable Network Security, Inc.");

 exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


function readable_ip()
{
 local_var r;

 r = _FCT_ANON_ARGS[0];
 return strcat(getbyte(blob:r, pos:0), ".",
	       getbyte(blob:r, pos:1), ".",
	       getbyte(blob:r, pos:2), ".",
	       getbyte(blob:r, pos:3));
}


port = 5351;
if (!service_is_unknown(port:port, ipproto:"udp")) exit(0, "The service listening on UDP port " + port + " has already been identified.");

if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

pkt = mkbyte(0) +  # Protocol version
      mkbyte(0);   # Request public IP address

send(socket:soc, data:pkt);
r = recv(socket:soc, length:1024);
close(soc);

if ( isnull(r) ) exit(0, "NAT-PMP not listening on the remote host.");
if ( strlen(r) < 4 ) exit(1, "NAT-PMP sent an unexpected answer.");
if ( getword(blob:r, pos:2) != 0 ) exit(1, "NAT-PMP rejected our query.");
if ( strlen(r) < 12 ) exit(1, "NAT-PMP sent an unexpected answer.");

public_ip = readable_ip(substr(r, 8, 11));
set_kb_item(name:"Services/udp/nat-pmp", value:port);
set_kb_item(name:strcat("nat-pmp/", port, "/public-ip"), value:public_ip);
if ( !islocalnet() )
{
 report += 'According to the remote NAT-PMP service, the public IP address of this host is :\n\n' + public_ip;

 listen =  bind_sock_tcp();
 soc = open_sock_udp(port);
 pkt = mkbyte(0) + # Protocol version = 0
       mkbyte(2) + # Map TCP
       mkword(0) + # Reserved
       mkword(listen[1]) + # Internal port
       mkword(listen[1]) + # Suggested external port
       mkdword(60);     # Lifetime

 send(socket:soc, data:pkt);
 r = recv(socket:soc, length:1024);
 close(soc);
 if ( strlen(r) >= 12 )
 {
 result = getword(blob:r, pos:2);
 internal_port = getword(blob:r, pos:8);
 mapped_port = getword(blob:r, pos:10);
 if ( result == 0 ) # Success
 {
  pkt = mkbyte(0) + # Protocol version = 0
      mkbyte(2) + # Map TCP
      mkword(0) + # Reserved
      mkword(internal_port) + # Internal port
      mkword(mapped_port) + # Suggested external port
      mkdword(0);     # Lifetime

 soc = open_sock_udp(port);
 send(socket:soc, data:pkt);
 r = recv(socket:soc, length:1024);
 close(soc);
 report += '\nIt was possible to create (and destroy) a mapping from ' + public_ip + ':' + mapped_port + ' to ' + compat::this_host() + ':' + internal_port;
 }
 else report += '\nIt was not possible to create a mapping.';
 }

 security_hole(port:port, proto:'udp', extra:report);
}
