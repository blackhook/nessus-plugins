#TRUSTED 4672e102373d2d88b60c40a59b065f5132f079e1d1dbfe07e68bb664e845ad60401dcf93302a93b692823cc82414d6b97495bfb1c2d103615e8c3a04ca1a52cd02a508cb9b42df42b15455abe0fa6edd676fb68ad95185aa081092bf1f9a0af27b074d4fbc98973309d0bf112ce2fe5e61e2f817cec490c249c12858ee7ecbf208209e533f3e3a2d45aac913e3eda16befe26313f605ae0ef743326871221461b553624f762445bede60b82922a67cb175f1bdc1eafb13103490d0bd13907569bcfe1be431f122143957fb00c38bf7b329cd25174da26e6e7b032de18b0a886c9eff629896f8be3ea7465d8d0bdbe85ad97ff8ba04cd4046cf9ed536307f6b0d7ec90badae3c07410fd52dfeb73f83fd5d87dfde8c74a7d13650905d15a963d85d0cf6208974a6f1e5844e81376f33a7b7c285bde0a777d6c7fb2fdfc9fb63ec0493cfd4dbdf69b4ef78b6b9074fec0030942edc59e7781c2dea0e036fc69c4c5464d564640e7e3d4e0f9bfc4dadf8a5f1c71c3462d8316beb213c8f8662847fac764db9bcd2650df8af714a7472fc0abd9d531508724c86c45c3d613b0bee8cfe63980284bb0d8e4ef7bd571175f444c77afe82fd33c5f76ace2923155a58bb67a3ddaca03369c19d7fa0abb9a852c1653afb66ddfe5334a7e858084e3f7c9736db1faf818f548eee1da86c1c9acca9d4043a98b699d3ce5d499dfc43ae8812
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("recvfrom")) exit(1, "recvfrom() not defined.");

include("compat.inc");

if (description)
{
  script_id(64631);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"HP LeftHand OS Console Discovery Detection");

  script_set_attribute(attribute:"synopsis", value:
"A discovery service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The HP LeftHand OS (formerly SAN/iQ) console discovery service, used
by systems such as the HP Virtual SAN Appliance, is running on the
remote host. This service allows management applications to discover
storage nodes.");
  # https://h20392.www2.hpe.com/portal/swdepot/displayProductInfo.do?productNumber=StoreVirtualSW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cc8713e");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:san/iq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 27491);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( TARGET_IS_IPV6 ) exit(1, "IPv6 is not supported");

function check_results(data, port, udp)
{
  local_var fields, report, group;
  if (isnull(data))
    return FALSE;

  fields = split(data, sep:'\x00', keep:FALSE);
  if (fields[0] != 'NSMreply:ver0.01')
    return FALSE;

  report = '';

  if (fields[3] != '')
    report += '\n  MAC address : ' + fields[3];
  if (fields[5] != '')
    report += '\n  Hostname : ' + fields[5];
  if (fields[8] != '')
    report += '\n  RAID configuration : ' + fields[8];
  if (fields[9] != '')
  {
    if (udp)
      set_kb_item(name:'lefthand_os/udp/' + port + '/version', value:fields[9]);
    else
      set_kb_item(name:'lefthand_os/' + port + '/version', value:fields[9]);
    report += '\n  Software version : ' + fields[9];
  }
  if (fields[11] != '')
  {
    group = fields[11];
    if (group == 'NO_SYSTEM_ID')
      group = 'none';
    report += '\n  Management group : ' + group;
  }
  if (fields[13] != '')
    report += '\n  Model : ' + fields[13];

  # the plugin can always expect to get some kind of results.
  # if there were no results, it's possible this is some other protocol
  if (report == '')
    return FALSE;

  if (udp)
    register_service(port:port, proto:'saniq_console_discovery', ipproto:'udp');
  else
    register_service(port:port, proto:'saniq_console_discovery');

  replace_kb_item(name:"HP/LeftHandOS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to gather the following information :\n' +
      report + '\n';
    if (udp)
      security_note(port:port, extra:report, proto:'udp');
    else
      security_note(port:port, extra:report);
  }
  else
  {
    if (udp)
      security_note(port:port, proto:'udp');
    else
      security_note(port:port);
  }

  return TRUE;
}

# first check UDP 27491
port = 27491;
soc = open_sock_udp(27491);
if (soc)
  soc2 = bind_sock_udp();

# don't know what this function does when it fails, but this seems like a reasonable check
if (!isnull(soc2) && soc2[0])
{
  recv_soc = soc2[0];
  sport = soc2[1];

  req =
    'NSMRequest:ver0.01\x00' +
    sport + '\x00' +
    '14\x00' +
    'UDP_DIRECT:' + get_host_ip() + '\x00';
  send(socket:soc, data:req);
  close(soc);

  res = recvfrom(socket:recv_soc, src:get_host_ip(), port:sport);
  close(recv_soc);
  udp_detected = check_results(data:res[0], port:port, udp:TRUE);
}

# then check TCP. the plugin forks at this point if thorough_tests is enabled
if (thorough_tests)
{
  port = get_unknown_svc(27491);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (!silent_service(port)) audit(AUDIT_FN_FAIL, 'silent_service', strcat('false for port ', port));
}
else port = 27491;
if (known_service(port:port)) exit(0, 'The service listening on port ' + port + ' has already been identified.');
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (soc)
{
  req =
    'NSMRequest:ver0.01\x00' +
    '3449\x00' +
    '14\x00' +
    'TCP_DIRECT:' + get_host_ip() + '\x00';
  send(socket:soc, data:req);

  # the length isn't sent in the response, it's just a stream
  # of null delimited fields. 2k should be more than enough
  res = recv(socket:soc, length:2048);
  close(soc);
  tcp_detected = check_results(data:res, port:port);
}

if (!udp_detected && !tcp_detected)
  exit(0, 'The service was not detected on UDP 27491 or TCP ' + port + '.');
else if (!udp_detected)
  audit(AUDIT_NOT_DETECT, 'Console Discovery', strcat(port, ' (UDP)'));
else if (!tcp_detected)
  audit(AUDIT_NOT_DETECT, 'Console Discovery', port);
