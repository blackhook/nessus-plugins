#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137053);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"ZDI", value:"ZDI-20-586");

  script_name(english:"Trading Technologies Messaging remove_park Stack Overflow");

  script_set_attribute(attribute:"synopsis", value:
"A security trading application running on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Trading Technologies Messaging (TTM) running on the remote
host is affected by a remote code execution vulnerability due to
the lack of validation of user-supplied data prior to copying it to a
fixed-length stack-based buffer when processing a remove_park
message. An unauthenticated, remote attacker can exploit this, via a
specially crafted message, to execute arbitrary code on the system
with SYSTEM privileges.

Note that the application is reportedly affected by other
vulnerabilities; however, this plugin has not tested for those issues.");
  script_set_attribute(attribute:"solution", value:
"Update the Trading Technologies Messaging to 7.1.28.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Correspond to ZDI CVSS3 score");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:trading_technologies:ttm");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tt_ttm_cmd_detect.nbin");
  script_require_ports("Services/tt_ttm_cmd", 10600);

  exit(0);
}

port = get_service(svc:'tt_ttm_cmd', default:10600, exit_on_fail:TRUE);
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_PORT_CLOSED, port);

post = ' not found in list of IPs to be parked';

# Overflow 200-byte stack buffer by one byte (sprintf appends a
# NULL char).
#
# The extra byte overflows a local variable that is not used if a
# non-empty string (i.e., ofdata) is passed to the remove_park
# function.
#
# The plugin does supply the non-empty string, so it's deem safe.
ofsize = 200 - strlen(post);

# This string is unlikely to be in the list of IPs to be parked.
# So the plugin is not going to change the state of the server.
ofdata = crap(data:'A', length:ofsize);
cmd = 'remove_park' + '\x00' + ofdata;
chk = ofdata + post;

login = ' qwed ' + SCRIPT_NAME;
req = login + ' ' + cmd + '\r\n';
send(socket: soc, data: req);
res = recv(socket:soc, length:1024);
close(soc);

# Vulnerable server reflects the contents in the overflowed buffer.
/*
0x0000:  6C 6F 67 69 6E 20 74 74 5F 74 74 6D 5F 7A 64 69    login tt_ttm_zdi
0x0010:  2D 32 30 2D 35 38 36 2E 6E 61 73 6C 0D 0A 00 52    -20-586.nasl...R
0x0020:  65 6D 6F 76 65 50 61 72 6B 20 53 74 61 72 74 20    emovePark Start
0x0030:  32 30 32 30 2F 30 35 2F 32 31 20 31 34 3A 33 36    2020/05/21 14:36
0x0040:  3A 30 38 3A 36 35 32 0D 0A 41 41 41 41 41 41 41    :08:652..AAAAAAA
0x0050:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA
*
0x00E0:  41 41 41 41 41 41 41 41 41 41 41 20 6E 6F 74 20    AAAAAAAAAAA not
0x00F0:  66 6F 75 6E 64 20 69 6E 20 6C 69 73 74 20 6F 66    found in list of
0x0100:  20 49 50 73 20 74 6F 20 62 65 20 70 61 72 6B 65     IPs to be parke
0x0110:  64 0D 0A 52 65 6D 6F 76 65 50 61 72 6B 20 45 6E    d..RemovePark En
0x0120:  64 20 20 20 32 30 32 30 2F 30 35 2F 32 31 20 31    d   2020/05/21 1
0x0130:  34 3A 33 36 3A 30 38 3A 36 35 32 0D 0A 00          4:36:08:652...
*/
if(chk >< res)
{
  extra = 'Nessus was able to detect the issue by sending a specially ' +
    'crafted remove_park message.'; 
  security_report_v4(port: port, severity: SECURITY_HOLE, extra: extra);
}
# Patched server uses vsnprintf_s() to ensure no overflow.
/*
0x0000:  6C 6F 67 69 6E 20 74 74 5F 74 74 6D 5F 7A 64 69    login tt_ttm_zdi
0x0010:  2D 32 30 2D 35 38 36 2E 6E 61 73 6C 0D 0A 00 52    -20-586.nasl...R
0x0020:  65 6D 6F 76 65 50 61 72 6B 20 53 74 61 72 74 20    emovePark Start
0x0030:  32 30 32 30 2F 30 35 2F 32 31 20 31 34 3A 33 36    2020/05/21 14:36
0x0040:  3A 35 37 3A 30 34 37 0D 0A 41 41 41 41 41 41 41    :57:047..AAAAAAA
0x0050:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA
*
0x00E0:  41 41 41 41 41 41 41 41 41 41 41 20 6E 6F 74 20    AAAAAAAAAAA not
0x00F0:  66 6F 75 6E 64 20 69 6E 20 6C 69 73 74 20 6F 66    found in list of
0x0100:  20 49 50 73 20 74 6F 20 62 65 20 70 61 72 6B 65     IPs to be parke
0x0110:  0D 0A 52 65 6D 6F 76 65 50 61 72 6B 20 45 6E 64    ..RemovePark End
0x0120:  20 20 20 32 30 32 30 2F 30 35 2F 32 31 20 31 34       2020/05/21 14
0x0130:  3A 33 36 3A 35 37 3A 30 34 37 0D 0A 00             :36:57:047...
*/
else
  audit(AUDIT_LISTEN_NOT_VULN, 'service', port);
