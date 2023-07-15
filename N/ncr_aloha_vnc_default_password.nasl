#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(108717);
  script_version ("1.2");
  script_cvs_date("Date: 2018/11/15 20:50:23");

  script_name(english:"NCR Aloha POS VNC Server 'aloha' Default Password");
  script_summary(english:"Attempts to authenticate with a password of 'aloha'.");

  script_set_attribute(attribute:"synopsis", value:
"A VNC server running on the remote host is secured with a default
password.");
  script_set_attribute(attribute:"description", value:
"The VNC server running on the remote NCR Aloha POS device is secured
with a default password. Nessus was able to login using VNC
authentication with a password of 'aloha'.  A remote, unauthenticated
attacker could exploit this to take control of the system.");
  # https://community.softwaregrp.com/t5/custom/page/page-id/HPPSocialUserSignonPage?redirectreason=permissiondenied&referer=https%3A%2F%2Fcommunity.softwaregrp.com%2Ft5%2FArchived-Security-Research-Blog%2FHacking-POS-Terminal-for-Fun-and-Non-profit%2Fba-p%2F278079
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d03390cf");
  script_set_attribute(attribute:"solution", value:
"Secure the VNC service with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ncr:aloha_pos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibertech:aloha_pos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Misc.");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("ncr_aloha_pos_web_detect.nbin", "vnc_security_types.nasl");
  script_require_keys("installed_sw/NCR Aloha POS");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/vnc", 5900);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('network_func.inc');
include('byte_func.inc');
include('crypto_func.inc');
include('install_func.inc');

get_install_count(app_name:"NCR Aloha POS", exit_if_zero:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

function connection_refused(port, socket)
{
 local_var reason, r, l, error;

 r = recv(socket: socket, min: 4, length: 4);
 if (strlen(r) == 4)
 {
   l = ntohl(n: r);
   reason = recv(socket: socket, length: l);
 }

 error = 'The remote VNC server rejected the connection';
 if (!empty(reason))
   error += '. Reason : ' + reason;

 close(socket);
 audit(AUDIT_RESP_BAD, port, 'authentication request. ' + error);
}


port = get_service(svc:'vnc', exit_on_fail:TRUE);
types = get_kb_list_or_exit('VNC/SecurityType/' + port);
vnc_auth = FALSE;

foreach type (types)
{
  if (type == 2)
  {
    vnc_auth = TRUE;
    break;
  }
}

if (!vnc_auth)
  exit(0, 'VNC Authentication is not supported on port ' + port + '.');

s = open_sock_tcp(port);
if (!s) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: s, length: 512, min: 12);
if (strlen(r) < 12)
{
  close(s);
  audit(AUDIT_RESP_BAD, port);
}

v = pregmatch(string: r, pattern: '^RFB ([0-9]+)\\.([0-9]+)\n');
if (isnull(v))
{
  close(s);
  audit(AUDIT_RESP_BAD, port);
}

major = int(v[1]);
minor = int(v[2]);

# Send back the same protocol
send(socket: s, data: r);

vnc_auth = FALSE;

if (major == 3 && minor >= 3 && minor < 7)
{
  r = recv(socket: s, min: 4, length: 4);
  if (strlen(r) != 4)
    exit(0, "The response was not the expected string length of 4.");

  st = ntohl(n: r);
  if (st == 0)
    connection_refused(port: port, socket: s);
  else if (st == 2)
    vnc_auth = TRUE;
}
else if (major > 3 || minor >= 7)
{
  r = recv(socket: s, min: 1, length: 1);
  if (strlen(r) < 1)
    exit(1, "An empty response was received.");

  n = ord(r);
  if (n == 0) # rejected connection
  {
   connection_refused(port: port, socket: s);
  }
  else
  {
   types = recv(socket:s, min:n, length:n);

   for (i = 0; i < strlen(types); i ++)
   {
     st = ord(types[i]);
     if (st == 2)
     {
       send(socket: s, data: '\x02');
       vnc_auth = TRUE;
     }
    }
  }
}
else
{
  close(s);
  exit(1, 'An unknown version of the RFB protocol used on port ' + port + '.');
}

if (!vnc_auth)
{
  close(s);
  exit(0, 'VNC Authentication is not supported on port ' + port + '.');
}

challenge = recv(socket: s, min: 16, length: 16);
if (strlen(challenge) != 16)
{
  close(s);
  audit(AUDIT_RESP_BAD, port);
}

# http://www.vidarholen.net/contents/junk/vnc.html
#
# each byte in the password needs to be reversed
# e.g., 00001111 needs to be changed to 11110000
password = 'aloha' + raw_string(0x00, 0x00, 0x00); # padding needed since the pw is less than 8 chars
reverse_pw = NULL;

for (i = 0; i < strlen(password); i++)
{
  c = ord(password[i]);

  tmp = 0;

  for (j = 0; j < 8; j++)
  {
    if ((c >>> j) & 1)
      tmp = tmp | (1 << (7 - j));
  }

  reverse_pw[i] = raw_string(tmp);
}

pos = 0;
response = NULL;

while (pos < strlen(challenge))
{
  dec = substr(challenge, pos, pos+7);
  response += DES (in:dec, key:set_des_key(key:reverse_pw), _string:FALSE, type:1);
  pos += 8;
}

send(socket:s, data:response);
security_result = recv(socket: s, min: 4, length: 4);
close(s);

if (strlen(security_result) != 4)
  audit(AUDIT_RESP_BAD, port);

security_result = getdword(blob:security_result, pos:0);
if (security_result != 0)  # 0 = OK, 1 = failed
  audit(AUDIT_HOST_NOT, 'affected');

report = '\nNessus logged in using a password of "aloha".\n';

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
