#TRUSTED 71ee818e80495123e9078f7eabfce26080ebbfa4c2b6d6be842f94b86768eeb472c739d74092614aa522141c51c4af2ae5dd521d6940a9b887112d78524217164314a698d217b293766f029248752d39280b8ccb9ee9be3a22c9bb7d0a786182bef41eba490c0f36cb730fb9462308b1f05eb2c31156687a99d28f5f05af2d8e3d7ff4e6436939d31130cbb229533abc9b0db07bcd98d04aface528162ede4394b5263a3353782636f639990aec088b1ecf5ca72e953cd644f5ca35887f7b4a36fb719fc79f72b61500ca6f886fef3c7bdd57adbfd7e1235bbfabacf347825a58129876eb8238e2794c6b63489ba743fe880011449afd61d1edd94e5aa3fdc06a127be9e1b5a10ff28c86c8c68f0f3a474a61e0c792c8e5db8b6bee41662b186a361e99fe959a27e5e1054032367bf290a8243821a18016879a87dbd0f8637b346f79882982a95b82936567b7fcdf86cd0160bbb64d35eef318bd8f03ec4ea7d483e2ebbb57ac545e86a5aec20dfd1b2ea3d8bc35c46705eae36200ebc41ff823421f0296a10cc35a566a955d8eb4ece86315a10751ea7a7099faaf8294fe0de21d37b7a86d54924c8f7eef5ed7110f7e8586005038e7009d2b93c4c627f8327ce2bc7a16ca359fbfe2cd19c51f0fa12da754a28f0f9e933ff049ecfa183640018f82b12564638fb7447ae4e75b4471b166c97c698900e59b39dd7e47fd41b4c
###
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47040);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/15");

  script_bugtraq_id(31289, 40320);
  script_xref(name:"Secunia", value:"39856");

  script_name(english:"FTP Daemon Long Command XSRF");
  script_summary(english:"Attempts to run a command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a cross-site request forgery
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FTP running on the remote host is affected by a
cross-site request forgery vulnerability. Long file names are not
processed properly, resulting in the execution of arbitrary commands. 

If a user is logged into the FTP server via web browser, a remote
attacker could exploit this by tricking them into requesting a
maliciously crafted web page, resulting in the execution of arbitrary
FTP commands.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/May/282");
  script_set_attribute(attribute:"see_also", value:"https://cxsecurity.com/issue/WLB-2010050127");
  script_set_attribute(attribute:"see_also", value:"https://cxsecurity.com/issue/WLB-2008090066");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/05/21");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/06/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

port = get_ftp_port(default:21);

user = get_kb_item('ftp/login');
pass = get_kb_item('ftp/password');
if (isnull(user))
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  user = 'anonymous';
}
if (isnull(pass))
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  pass = 'nessus@nessus.org';
}

soc = ftp_open_and_authenticate( user:user, pass:pass, port:port );
if ( !soc )
{
  exit(1, 'Authentication failed for user "'+user+'" on port '+port+'.');
}

send(socket:soc, data:'PWD\r\n');
r = recv_line(socket:soc, length:4096);

cmd = SCRIPT_NAME+'-'+unixtime();
csrf = 'SIZE ' + crap(data:'/', length:2042) + cmd + '\r\n';
whole_response = '';

send(socket:soc, data:csrf);
r = recv_line(socket:soc, length:4096);
if (!strlen(r)) audit(AUDIT_RESP_NOT, port);

# Response / Cmd splitting comes as multiple responses
# so we loop to catch them all and then check
while (strlen(r)>0)
{
  whole_response += '\n'+r;
  r = recv_line(socket:soc, length:4096);
}

close(soc);

# vuln response looks like the following lines:
#
# 500 SIZE ////////...: command not understood
# 500 /////////////...: command not understood
# 500 /////////////...: command not understood
# 500 /////////////...: command not understood
# 500 ///FTP.NASL-1559738684: command not understood.
#
if (whole_response =~ '500[\\s\'\"]*\\/*'+cmd+'[\\s\'\"]*:\\s*command not understood')
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  security_report_v4(severity:SECURITY_WARNING, port:port, generic:TRUE, output:whole_response, request:[csrf]);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
