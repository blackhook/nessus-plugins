#TRUSTED 02f3a9d18e213ea7c95f40f14c10762169378454f8a32b04eead07e17274b494e26f513950b9acc560aa4929044b68871dd46ed184335fbfe0940db6418c78fdda731c0a070fb20171bc38a1824ba16d6832bd9db8f592051c8b2dbdc52041070603a6d1b02b012e12698116bfe2cb60bd753e202495c35ca108314a3f99a2f81e51724f550140fea326dec893ed10fef86ca4eeaed376f48b9e0603500b9ad7b69ad5596dd15c4a8e69ae8dc30b0e256681b3343bdf23796337db593e174fd774076b18e2e3366b35ee908e0c09455b9b7be96ee64fb52f582012b1684776ce96c661645e4b8b8751621c3ef8646fc0dc9660762cc4a2efc61b59d0cafdfa6188d3e5a45929929a46a52101af2c1b0a310cca2d8cd682a71839870a736b9cfea0976ce0b9fd281fc1135de18187c1b8700db130b78088a54e9dff44bebaca810b285430be969b619b3d29692826cf6f2512b44b5ad99d845eba6139a92258dbd74c3feb3477eb4b7610655b6e5af9d43d6c91dfe593fb77b8669797e0a7de26d785dd60b50460e72f200002cbe1f3f5e01f78351e1350c649be178b68bbcc6215c1ec13e6713100543b29fb3e4fc57da18b6930e4bc3755bc5262c8c118dd81277000b2beeba65371233f5002532634864640f0f5530a0d3544fb276bfc2f5fe11a151e951f652274518a9d66f40c2c21a89061c15e36566d8f3b3161873640
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69181);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/01/22");

  script_name(english:"OS Identification : NETCONF Over SSH");
  script_summary(english:"Authenticates via SSH and looks for a netconf hello");

  script_set_attribute(attribute:"synopsis", value:
"It may be possible to fingerprint the remote host's operating system
by querying its management protocol."
  );
  script_set_attribute(attribute:"description", value:
"The remote host is using the NETCONF protocol over SSH.  The NETCONF
protocol is used to manage network devices.

It may be possible to determine the operating system name and version
by using the SSH credentials provided in the scan policy."
  );
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc6241");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_settings.nasl", "ssh_check_compression.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');


enable_ssh_wrappers();

##
# Sends a netconf payload over an already-established SSH channel,
# wrapping it in a SSH_MSG_CHANNEL_DATA header
#
# @anonparam data netconf request
# @return whatever send_ssh_packet() returns (don't know if that functions returns anything)
##
function _netconf_send()
{
  local_var data, payload;
  data = _FCT_ANON_ARGS[0];
  payload =
    raw_int32(i:remote_channel) + # global from ssh_func.inc
    putstring(buffer:data);

  return send_ssh_packet(payload:payload, code:raw_int8(i:94));
}

##
# Receives a netconf payload, removing the SSH-related header
#
# @return netconf payload
##
function _netconf_recv()
{
  local_var res, payload;
  res = recv_ssh_packet();
  payload = substr(res, 9); # code, channel, and length ignored
  return payload;
}

port = kb_ssh_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

if ( port && get_port_state(port) )
{
  soc = open_sock_tcp(port);
  if ( soc )
  {
    ssh_banner = recv_line(socket:soc, length:1024);
    close(soc);
    if ( "-Cisco-" >< ssh_banner )
    {
      CISCO++;
      if ("-Cisco-2." >< ssh_banner) CISCO_IOS_XR++;
    }
  }
}

# nb: needed for Cisco Wireless LAN Controllers and Sonicwall.
if (!CISCO)
{
  set_kb_item(name:"/tmp/ssh/try_none", value:TRUE);
  timeout = get_ssh_read_timeout();
  if (timeout <= 5) set_ssh_read_timeout(10);
}

# nb: needed for Cisco IOS XR
if (CISCO_IOS_XR) sleep(1);

if ("force10networks.com" >< ssh_banner) sleep(1);

success = ssh_open_connection();

# nb: Sonicwall needs a delay between the initial banner grab
#     and  calling 'ssh_open_connection()'.
if (
  !success &&
  "please try again" >< get_ssh_error()
)
{
  for (i=0; i<5 && !success; i++)
  {
    # We need to unset login failure if we are going to try again
    if(get_kb_item("SSH/login/failed")) rm_kb_item(name:"SSH/login/failed");
    sleep(i*2);
    success = ssh_open_connection();
  }
}

if (!success)
{
  error = get_ssh_error();
  if (strlen(error) == 0)
    msg = 'SSH authentication failed on port ' + port + ': unknown error.';
  else
    msg = 'SSH authentication failed on port ' + port + ': ' + error;
  exit(1, msg);
}

ssh_protocol = get_kb_item("SSH/protocol");
if (!isnull(ssh_protocol) && ssh_protocol == 1) exit(0, "The SSH server listening on port "+port+" only supports version 1 of the SSH protocol.");


ret = ssh_open_channel();
if (ret != 0)
{
  ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, 'SSH', port);
}

# SSH_MSG_CHANNEL_REQUEST
channel_req =
  raw_int32(i:remote_channel) +
  putstring(buffer:'subsystem') +
  raw_int8(i:1) +  # want reply
  putstring(buffer:'netconf');
send_ssh_packet(payload:channel_req, code:raw_int8(i:98));

# skip over any packets that we don't care about
res = recv_ssh_packet();
while((ord(res[0]) == 93) || (ord(res[0]) == 95) || (ord(res[0])  == 98))
{
  if (ord(res[0]) == 95)
  {
    payload = getstring(buffer:res, pos:9);
    _ssh_cmd_error += payload;
    val = update_window_size(size:strlen(payload));
    if (val != 0)
      break;
  }
  res = recv_ssh_packet();
}

if (ord(res[0]) == SSH2_MSG_CHANNEL_FAILURE)
{
  ssh_close_connection();
  audit(AUDIT_NOT_LISTEN, 'netconf', port);
}
else if (ord(res[0]) != SSH2_MSG_CHANNEL_SUCCESS) # expected response
{
  if (!bugged_sshd) ssh_close_channel();
  ssh_close_connection();
  audit(AUDIT_RESP_BAD, port, 'netconf subsystem request');
}

res = recv_ssh_packet();
while((ord(res[0]) == 93) || (ord(res[0]) == 95) || (ord(res[0])  == 98))
{
  if (ord(res[0]) == 95)
  {
    payload = getstring(buffer:res, pos:9);
    _ssh_cmd_error += payload;
    val = update_window_size(size:strlen(payload));
    if (val != 0)
      break;
  }
  res = recv_ssh_packet();
}

hello = substr(res, 9);
if (hello !~ '^<hello' || 'netconf' >!< hello)
{
  ssh_close_connection();
  audit(AUDIT_NOT_LISTEN, 'netconf', port);
}

set_kb_item(name:'Host/netconf/' + port + '/hello', value:hello);

# Juniper IVE SA & IVE IC
if (hello =~ '<capability>http://xml.juniper.net/dmi/ive-(sa|ic)')
{
  _netconf_send('<rpc message-id="1"><get-system-information /></rpc>');
  sys_info = _netconf_recv();
  _netconf_send('<rpc message-id="2"><close-session/></rpc>'); # cleanup, response ignored
  ssh_close_connection();

  if (sys_info !~ '<os-name>ive-(sa|ic)') # sanity check
    audit(AUDIT_RESP_BAD, port, 'get-system-information');

  os = 'Pulse Connect Secure (formerly Juniper IVE OS)';

  match = eregmatch(string:sys_info, pattern:'<os-version>([^<]+)</os-version>');
  if (isnull(match))
    audit(AUDIT_RESP_BAD, port, 'get-system-information');
  else
    version = match[1];

  match = eregmatch(string:sys_info, pattern:'<hardware-model>([^<]+)</hardware-model>');
  if (!isnull(match))
  {
    model = match[1];
    set_kb_item(name:'Host/netconf/' + port + '/model', value:model);
  }

  set_kb_item(name:'Host/netconf/' + port + '/os', value:'Juniper IVE OS');
  set_kb_item(name:'Host/Juniper/IVE OS/Version', value:version);
  set_kb_item(name:'Host/OS/netconf', value:'Juniper IVE OS ' + version);
  set_kb_item(name:'Host/OS/netconf/Confidence', value:100);
  set_kb_item(name:'Host/OS/netconf/Type', value:'embedded');

  if (report_verbosity > 0)
  {
    report =
      '\n  Operating system : ' + os +
      '\n  Version          : ' + version;
    if (!isnull(model))
      report += '\n  Model            : ' + model;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
else
{
  ssh_close_connection();

  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to access the NETCONF SSH subsystem but was' +
      '\n' + 'unable to identify the device based on its hello message :\n\n' +
      hello;
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
