#TRUSTED 7f3724d737a0b357b91f78faaee13c3a9b1ba0c91fa327e433b74271791b42dd9f22c8484e7fc121b4822e8cf9d7f08ad529f5498a3115646f540e6164e1f90d6f579cd8aaa18dcff8fb8f29fa76d012c9d66a588776c7d96e98f4619d52017b3f9366dce3a435d600717dc29926697e7aaa669f4d0dce64b2574dd25b3d22891f83288eb44dfc718ef398c51fa2108f88c00a29168a95d327ee92143dfd4b6610d21b026eb58cc3bf68ce8cf83e7b1b08c8dc9a1a412787b3b7a64a178d56a4b82091b961ecbbf8f9e5f861cacc597410653adf00f9e68704b83fae43ff7ca21e0e712e3dbdc0373aca57b1c0f543296eaf3166171d4076bdfaa1959747c2cac9f8fb4789f39ef69957061f6b9f9901274f8771632a3cf3e06e559c1fef12d95385e4c5c61bb467c1fdfec08c61abfd8a7f8ced10ce7a60df968dcd7ddeaea6ae0888f62765983e6ec82f46e7e6d49fd2da11bfc795d03e1e2ba74a12e079b422e2b0211629e72afa7dab39327e3d17d296eb30b925f85d9278dc0ba733c45163a9ab4152fbfc38ec9b0c335ae492c4be5463552fb0a7f32ae68cecce0a1ee2529a0fbec313f64acdb34093e4764ef04c182fd27ae69ea6e4883a7ed5b3b920023958bb4f0072effa76e864996e642db3615a61e7cfb0dc485aecc80cdee852728306903d5281cd0d46bf8112a5619c0651e2b3216c2412cecebfc5fea9acda
#TRUST-RSA-SHA256 6002e584d8df1c00c86ae2faa15116366bcf6806bdab4e3c281039ef176079f0ba83d5292db393c1ebc78c70f29eca1b6306dbffdc18b92446336d389f5bb2cdd0c930ff9810e2d7a4afcc752d264ca4767882717466875ae662918e19c31df5ec77755be92b122e151aa9c8edfc90ba9a2fa8ff35045935c7920bf9ade4dbccbedeed29084975ebbbbb31c98be4fd7e1db42f91b39266f82492a0b5b706ff893c0c6556b048866d205d4f8bda78e62c8c3a91aadafb1b1a9d2083826c859a8ada29c12d5c6ba893f2fccce78b945b3ec97787520c05dd5e4d3e2535e7d70119caf6f85d5f03d86d4d62f7f3708d151b74273caf836e01a3340bd5d081289a83f505c75fc4d7485edd92e2d7a94cb93c633ca2e33d89909bcd7e7653f944d53da74bf35dc067d762a871202807ca5f9555f2e3ca71c9b92535cdc5b0d891ca922b8a245865e918b4eb1c2a0247f0edc03b3400a0079fd5f3fe3d59de7ce26c1bbb7d7e593a05e2ad85493a3140aef26e72849ea816d7f1cf180085f08e8b413c19a6fb342256387a57b1f721f2fc3e9282ae2d04b85b261cf4b576c45b127867c22104e44fe8a036ba130ac40787a7b44e0ef72d72df0ce2d78b316bb4b8c49301097215183a7d36c4cd633eb0bb3b85fc00a7322242cc97df4b36bc9200860f2250a98c6d7f2850e76ad3950b4a14cf16264702a759efac61d6fa3c1d33c8b5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(14272);
  script_version("1.101");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_name(english:"Netstat Portscanner (SSH)");
  script_summary(english:"Find open ports with netstat.");

  script_set_attribute(attribute:'synopsis', value:
"Remote open ports can be enumerated via SSH.");
  script_set_attribute(attribute:'description', value:
"Nessus was able to run 'netstat' on the remote host to enumerate the
open ports. If 'netstat' is not available, the plugin will attempt to use 'ss'.

See the section 'plugins options' about configuring this plugin.

Note: This plugin will run on Windows (using netstat.exe) in the 
event that the target being scanned is localhost.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Netstat");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_SCANNER);
  script_family(english:"Port scanners");

  script_copyright(english:"This script is Copyright (C) 2004-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ping_host.nasl", "ssh_settings.nasl", "portscanners_settings.nasl", "ssh_rate_limiting.nasl");
  script_exclude_keys("Host/OS/ratelimited_sonicwall", "Host/OS/ratelimited_junos", "Host/OS/ratelimited_omniswitch");
  script_timeout(600);
  exit(0);
}

include("ports.inc");
include("lcx.inc");
include("agent.inc");
include("ssh_lib.inc");
include("ssh_compat.inc");
include("netstat.inc");

function run_cmd_by_sshlib(cmd)
{
  local_var session, channel, login_res, escl_method, escl_extra;

  var buf = NULL;
  session = new("sshlib::session");
  login_res = sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:FALSE);
  if(!login_res)
  {
    session.close_connection();

    # If it failed, remove the failure so that plugins down the chain can verify after
    # service detection.
    rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed");
    return NULL;
  }

  session.set_recv_timeout(60);
  escl_method = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + session.get_kb_connection_id() + "/escalation_type");
  if(!escl_method || "Nothing" >< escl_method)
  {
    buf = session.run_exec_command(command:cmd, cmd_timeout_min:120);
    if(empty_or_null(buf))
    {
      channel = session.open_shell(shell_handler:new("sshlib::sh_shell_handler"));
      if(!isnull(channel))
        buf = session.run_shell_command(channel:channel, command:cmd);
    }
  }
  else
  {
    channel = session.open_shell(shell_handler:new("sshlib::sh_shell_handler"));
    if(!isnull(channel))
    {
      escl_extra = sshlib::get_kb_args(kb_prefix:("Secret/" + sshlib::SSH_LIB_KB_PREFIX + session.get_kb_connection_id() + "/escalation_extra"));
      channel.shell_handler.set_priv_escalation(type:escl_method, extra:escl_extra);
      buf = session.run_shell_command(channel:channel, command:cmd, force_priv_escl:TRUE);
    }
    if(empty_or_null(buf))
    {
      buf = session.run_exec_command(command:cmd, cmd_timeout_min:120);
    }
    if(empty_or_null(buf))
    {
      channel.shell_handler.unset_priv_escalation();
      if(!isnull(channel))
        buf = session.run_shell_command(channel:channel, command:cmd);
    }
  }

  session.close_connection();
  return buf;
}

if(isnull(get_kb_item("/tmp_start_time")))
  replace_kb_item(name: "/tmp/start_time", value: unixtime());

if ( get_kb_item("PortscannersSettings/run_only_if_needed") &&
     get_kb_item("Host/full_scan") )
  exit(0, "The remote host has already been port-scanned.");

if (get_kb_item("Host/OS/ratelimited_sonicwall") ||
    get_kb_item("Host/OS/ratelimited_junos") ||
    get_kb_item("Host/OS/ratelimited_omniswitch"))
  exit(1,"This plugin does not run against rate limited devices.");

# If plugin debugging is enabled, enable packet logging
if(get_kb_item("global_settings/enable_plugin_debugging"))
  SSH_LOG_PACKETS = TRUE;

buf = "";
ssh_banner = "";
n_tcp = 0; n_udp = 0;

# On the local machine, just run the command
if (lcx::check_localhost())
{
  buf = netstat::run_localhost_netstat();
  if ( buf )
  {
    set_kb_item(name:"Host/netstat", value:buf);
    set_kb_item(name:"Host/netstat/method", value:"local");
    if (agent())
    {
      agent_ip = agent_get_ip();
      if(!isnull(agent_ip))
        report_xml_tag(tag:"host-ip", value:agent_ip);
    }
  }
  else exit(1, "Failed to run the command 'netstat -a -n' on localhost.");
}
else if ( get_kb_item("Secret/SSH/login") )
{
  port22 = kb_ssh_transport();
  if ( port22 && get_port_state(port22) )
  {
    _ssh_socket = open_sock_tcp(port22);
    if ( _ssh_socket )
    {
      ssh_banner = ssh_exchange_identification();

      ssh_close_connection();
      if (
         "-cisco-" >< tolower(ssh_banner) ||
         "-cisco_" >< tolower(ssh_banner)
      ) exit(0, 'The netstat portscanner doesn\'t run against Cisco devices.');
    }
  }

  # Need to set try none for Sonicwall
  set_kb_item(name:"/tmp/ssh/try_none", value:TRUE);
  timeout = get_ssh_read_timeout();
  if (timeout <= 5) set_ssh_read_timeout(10);

  if ("force10networks.com" >< ssh_banner) sleep(1);

  ret = ssh_open_connection();

  # nb: Sonicwall needs a delay between the initial banner grab
  #     and  calling 'ssh_open_connection()'.
  if (
    !ret &&
    "please try again" >< get_ssh_error()
  )
  {
    for (i=0; i<5 && !ret; i++)
    {
      # We need to unset login failure if we are going to try again
      if(get_kb_item("SSH/login/failed")) rm_kb_item(name:"SSH/login/failed");
      sleep(i*2);
      ret = ssh_open_connection();
    }
  }

  cmd = "cmd /c netstat -an";
  if (ret)
  {
    buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, timeout:60);
  }
  else
  {
    ssh_close_connection();
  }

  if (get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed") &&
      get_kb_item("SSH/login/failed"))
  {
    exit(1, "Failed to open an SSH connection.");
  }

  if('Command Line Interface is starting up, please wait' >< buf)
  {
    ssh_close_connection();
    exit(0, 'The netstat portscanner doesn\'t run against Cisco devices.');
  }

  if ("LISTENING" >!< buf && "0.0.0.0:0" >!< buf && "*.*" >!< buf)
  {
    # Brocade
    if (
      !buf &&
      'rbash: sh: command not found' >< ssh_cmd_error()
    )
    {
      if(!ret)
      {
        sock_g = ssh_open_connection();
        if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      }

      cmd = "netstat -an";
      buf = ssh_cmd(cmd:cmd, nosh:TRUE, timeout:60);
    }
    # NetApp Data ONTAP
    else if (
      !buf &&
      "cmd not found.  Type '?' for a list of commands" >< ssh_cmd_error()
    )
    {
      ssh_close_connection();
      sock_g = ssh_open_connection();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
    }
    #NetApp Data ONTAP clustered
    else if (
      !buf &&
      "Error: Ambiguous command" >< ssh_cmd_error() ||
      "is not a recognized command" >< ssh_cmd_error()
    )
    {
      ssh_close_connection();
      sock_g = ssh_open_connection();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "system node run -node local -command netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
      if ( !buf && "is not a recognized command" >< ssh_cmd_error() )
      cmd = "node run -node local -command netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
      if ( !buf && "is not a recognized command" >< ssh_cmd_error() )
      cmd = "run -node local -command netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
    }

    # ScreenOS
    else if (
      !buf &&
      "-NetScreen" >< ssh_banner
    )
    {
      ssh_close_connection();
      sock_g = ssh_open_connection();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "get socket";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
    }
    else
    {
      ssh_close_connection();

      cmd = 'netstat -a -n';
      /**
      - sshlib
      -- If there are no escalation credentials
      --- Try exec
      --- If that doesn't work, try sh shell handler
      -- If there are escalation credentials
      --- Try sh shell handler
      --- If that doesn't work
      ---- Try exec without credentials
      ---- If that doesn't work, try sh shell handler without credentials
      - If none of that worked, old lib
      -- ssh_cmd() with no extra args (will be either exec or shell depending on escalation)
      -- If that didn't work
      --- If there were no escalation creds, try noexec:TRUE to force shell
      --- If there were escalation creds
      ---- try ssh_cmd() with nosudo
      ---- if that didn't work, try ssh_cmd() with noexec

      **/ 
      buf = run_cmd_by_sshlib(cmd: cmd);
      if ('command not found' >< buf || 'No such file or directory' >< buf || ' not found, but can be installed with:' >< buf)
      {
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:"netstat not found, trying ss: buf: "+buf);
        # if netstat fails, try ss as a separate command
        // try ss
        # centos: /usr/bin/ss -a -n 
        # ubuntu: /usr/sbin/ss -a -n
        # debian: /bin/ss -a -n
        cmd = '(/usr/sbin/ss -n -a 2>/dev/null && echo 1)|| (/bin/ss -n -a 2>/dev/null && echo 2)|| (/usr/bin/ss -n -a 2>/dev/null && echo 3)';

        buf = run_cmd_by_sshlib(cmd: cmd);
      }
    }

    if (
      !buf ||
      "Cmd exec error" >< buf ||
      "Cmd parse error" >< buf ||
      "command parse error before" >< buf ||
      "(Press 'a' to accept):" >< buf ||
      "Syntax error while parsing " >< buf || 
      ' not found, but can be installed with:' >< buf
    ) { ssh_close_connection(); exit(1, "The 'netstat' command failed to be executed."); }
  }
  ssh_close_connection();
  set_kb_item(name:"Host/netstat", value:buf);
  set_kb_item(name:"Host/netstat/method", value:"ssh");
  if ('/ss' >< cmd)
    set_kb_item(name:'Host/netstat/cmd', value:'ss');
}
else exit(0, "No credentials are available to login to the host.");

ip = get_host_ip();
lines = split(buf);
n = max_index(lines);
if (n == 0) n = 1; i = 0;
scanner_status(current: 0, total: n);
scanned = 0;

check = get_kb_item("PortscannersSettings/probe_TCP_ports");


if ("yes" >< get_preference("unscanned_closed"))
  unscanned_closed = TRUE;
else
  unscanned_closed = FALSE;

if (unscanned_closed)
{
  tested_tcp_ports = get_tested_ports(proto: 'tcp');
  tested_udp_ports = get_tested_ports(proto: 'udp');
}
else
{
  tested_tcp_ports = make_list();
  tested_udp_ports = make_list();
}

discovered_tcp_ports = make_array();
discovered_udp_ports = make_array();

var v;
foreach var line (lines)
{
  line = chomp(line);
  # Windows
  v = netstat::process_netstat_win_line_open_ports(line:line);

  # Unix
  if (isnull(v))
    v = netstat::process_netstat_nix_line_open_ports(line:line);

  if (isnull(v))
    v = netstat::process_ss_nix_line_open_ports(line:line);

  # Solaris 9 / NetApp
  if (isnull(v))
  {
    if (last_seen_proto)
    {
      if (last_seen_proto == 'udp')
      {
        v = pregmatch(pattern: '^[ \t]*(?:::ffff[:.])?(\\*|[0-9.]+)\\.([0-9]+)[ \t]+Idle', string: line);
        if (isnull(v)) v = pregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+(\\*\\.\\*|[0-9.]+)[ \t]+[0-9]+[ \t]+[0-9]+$', string: line);
      }
      else
        v = pregmatch(pattern: '^[ \t]*(?:::ffff[:.])?(\\*|[0-9.]+)\\.([0-9]+)[ \t]+\\*\\.\\*[ \t]+.*(Idle|LISTEN)', string: line);

      if (! isnull(v))
      {
        # "Fix" array
        v[3] = v[2]; v[2] = v[1]; v[1] = last_seen_proto;
      }
    }
    if (isnull(v))
    {
      v = pregmatch(pattern: '^(TCP|UDP)(: +IPv4)?[ \t\r\n]*$', string: line);
      if (isnull(v)) v = pregmatch(pattern: '^Active (TCP|UDP) (connections|sockets) \\(including servers\\)[ \t\r\n]*$', string: line);
      if (!isnull(v))
      {
        last_seen_proto = tolower(v[1]);
        v = NULL;
      }
    }
  }

  # ScreenOS
  # Socket  Type   State      Remote IP         Port    Local IP         Port
  #    1  tcp4/6  listen     ::                   0    ::                443
  #    2  tcp4/6  listen     ::                   0    ::                 23
  #    3  tcp4/6  listen     ::                   0    ::                 22
  #   67  udp4/6  open       ::                   0    ::                500
  if (isnull(v))
  {
    v = pregmatch(pattern:'^[ \t]*[0-9]+[ \t]+(tcp|udp)4/6[ \t]+(listen|open)[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|::)[ \t]+[0-9]+[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|::)[ \t]+([0-9]+)[ \t]*', string:line, icase:TRUE);
    if (!isnull(v))
    {
      proto = v[1];
      state = v[2];
      local_ip = v[4];
      local_port = v[5];

      # "Fix" array
      v[1] = proto;
      v[2] = local_ip;
      v[3] = local_port;
    }
  }

  if (!isnull(v))
  {
    proto = tolower(v[1]);
    addr = v[2];
    port = int(v[3]);
    checktcp = (check && proto == "tcp");

    if (port < 1 || port > 65535)
    {
      spad_log(message:'netstat_portscan(' + get_host_ip() + '): invalid port number ' + port + '\n');
    }

    # no loopback addresses, unless target is localhost
    addr_parts = split(addr, sep:".");
    if ((addr_parts[0] == "127." || addr == "::1") && addr != ip)
      continue;

    if (unscanned_closed)
      if (
        (proto == "tcp" && ! tested_tcp_ports[port]) ||
        (proto == "udp" && ! tested_udp_ports[port])
      ) continue;

    if (
      (proto == "tcp" && discovered_tcp_ports[port]) ||
      (proto == "udp" && discovered_udp_ports[port])
    ) continue;

    if (checktcp)
    {
      soc = open_sock_tcp(port);
      if (soc)
      {
        scanner_add_port(proto: proto, port: port);
        close(soc);
      }
    }
    else
    {
      scanner_add_port(proto: proto, port: port);
    }

    if (proto == "tcp")
    {
      n_tcp ++;
      discovered_tcp_ports[port]++;
    }
    else if (proto == "udp")
    {
      n_udp ++;
      discovered_udp_ports[port]++;
    }
    scanned ++;
  }
  scanner_status(current: i++, total: n);
}

if (scanned)
{
  set_kb_item(name: "Host/scanned", value: TRUE);
  set_kb_item(name: "Host/udp_scanned", value: TRUE);
  set_kb_item(name: "Host/full_scan", value: TRUE);

  set_kb_item(name:"NetstatScanner/TCP/OpenPortsNb", value: n_tcp);
  set_kb_item(name:"NetstatScanner/UDP/OpenPortsNb", value: n_udp);

  set_kb_item(name: "Host/TCP/scanned", value: TRUE);
  set_kb_item(name: "Host/UDP/scanned", value: TRUE);

  set_kb_item(name: "Host/TCP/full_scan", value: TRUE);
  set_kb_item(name: "Host/UDP/full_scan", value: TRUE);

  set_kb_item(name: 'Host/scanners/netstat', value: TRUE);
}

scanner_status(current: n, total: n);
