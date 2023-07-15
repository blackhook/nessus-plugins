#TRUSTED 176b93fb00a1592b48392bd4cfb8577c78403ed93e063ba45b98adc846580f18cccfe61eecdee1fb6a883af99b6060ab69e40914eb3bcee39129955ca9eeb454597f4b822d6d3ba4c6fb48ec988da13920fee3d6932bd0e66ff1e4dada7689eec85c7f94d31a3200da4f58c1b10aa67edf7bec206fcbe0ead5397d1d93490dcbfdc8b30503a5ff2711284b05ee2e7bd2ccb849ee1366ff0bf1eb1b962795131c4d3035c485bc4315fc67cd51f3ec87789f844fa1d45e71cd9d60d5d6f09bb284e85fdfc2462e941d2de16694ea27a2d5f5edc4b0e86e2694b597b3e16930b2749ad64fcfe746d0d1d9fcf0067e2001ad86b25f72ac672451f83147ad055a2e80d31cc0cdda52ac2887c20ef49df0d4efd5ee0c0554db342fb1784b309e0e43e0ff0290a40cb18630241f7e140573d01badca1fe7ae52676a42898c959e51e26aee5e991750bcf46c2a2f8fe8cab108f2b6132d8a465ea7e1a5d803a90c28c9a31f3f1795640bfbbf48d20c7dee566e2fcdef183a898bd631523464d3063ca894e3e84ea0751de467538961156fcfa1b2e0f4ab0e190d3e94485616be34fc53af1b6ef02367e83083c0c24e0a4557f3fc779e1e7e12a8d516c2ca06ad7edb9b36e6f5113b092d69c3bfe5a530303309357bd8c2669fb5fd84bb95ecd8f87951b0be9f6b6012bd6b21b294af71e391f20dde57eaebc9ae415502ad77da01e9943e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25221);
 script_version("1.26");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

 script_name(english:"Remote listeners enumeration (Linux / AIX)");
 script_summary(english:"Finds the process listening on each port with netstat.");

 script_set_attribute(attribute:"synopsis", value:
"Using the supplied credentials, it was possible to identify the
process listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"By logging into the remote host with the supplied credentials, Nessus
was able to obtain the name of the process listening on the remote
port.

Note that the method used by this plugin only works for hosts running
Linux or AIX.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22, "nessus/product/agent");
 script_require_keys("Host/uname");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

uname = get_kb_item_or_exit("Host/uname");
if (
  'Linux' >!< uname &&
  'AIX' >!< uname
) audit(AUDIT_HOST_NOT, "Linux / AIX");

# We may support other protocols here
if ( islocalhost() )
 info_t = INFO_LOCAL;
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(0);
 info_t = INFO_SSH;
}

# nb: On Solaris, you can do this with a command like:
#
#     pfexec pfiles `ls /proc` 2>/dev/null | egrep '^[0-9]|port:'
#
#     The problem is that pfiles, as its man page warns, can cause a process
#     to stop while its being inspected by the tool, and that is to be
#     avoided in a production environment!


cmdlines = make_array();
localaddrs = make_array();
exes = make_array();
pids = make_array();
prelinked = make_array();
md5s = make_array();

if ("Linux" >< uname)
{
  buf = info_send_cmd(cmd:"prelink -p 2>/dev/null");
  # sanity check
  if('objects found in prelink cache' >< buf)
  {
    foreach entry (split(buf, sep:'\n', keep:FALSE))
    {
      # only interested in binaries, the code below
      # will filter out the libraries
      if(':' >< entry && entry !~ "\[0x[a-zA-Z0-9]+\]")
      {
        item = pregmatch(pattern:"^([^:]+):", string:entry);
        if(!isnull(item)) prelinked[item[1]] = TRUE;
      }
    }
  }

  netstat_cmd = "netstat -anp";
  buf = info_send_cmd(cmd:"LC_ALL=C "+netstat_cmd);
  if (strlen(buf) == 0)
  {
    errmsg = ssh_cmd_error();
    if (errmsg) errmsg ='for the following reason :\n\n' + errmsg + '\n\n';
    else errmsg = 'for an unknown reason. ';
    errmsg = "Failed to run '" + netstat_cmd + "' " + errmsg;
    if (info_t == INFO_SSH) ssh_close_connection();
    exit(1, errmsg);
  }
  set_kb_item(name:"Host/netstat_anp", value:buf);

  foreach line (split(buf, keep:FALSE))
  {
    v = pregmatch(string:line, pattern:'^(tcp|udp)[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+\\.[0-9.]+):([0-9]+)[ \t]+([0-9]+\\.[0-9.]+):[0-9*]+[ \t]+(LISTEN[ \t]+)?([0-9]+)/([^ \t].*)?[ \t]*$');
    if (isnull(v))  # Try IPv6 *even* if the target is IPv4
      v = pregmatch(string:line, pattern:'^(tcp|udp)6?[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9a-f:]+):([0-9]+)[ \t]+([0-9a-f:]+):[0-9*]+[ \t]+(LISTEN[ \t]+)?([0-9]+)/([^ \t].*)?[ \t]*$');
    if (isnull(v)) continue;

    port = int(v[3]);
    if (port < 0 || port > 65535) continue;
    proto = tolower(v[1]);
    if (proto != "tcp" && proto != "udp") continue;

    pid = int(v[6]);

    k = strcat(proto, '/', port);
    if (exes[k]) continue;

    if (pid > 0)
    {
      exe = info_send_cmd(cmd:"LC_ALL=C "+'readlink \'/proc/'+pid+'/exe\' 2>/dev/null');
      if (strlen(exe) > 0) exe = chomp(exe);

      # check md5sum of process image for further verification if needed  (used in daemons_with_broken_links.nasl)
      if(isnull(md5s[pid]) && preg(pattern:"^(.+) \(deleted\)$", string:exe))
      {
        exe_md5sum = info_send_cmd(cmd:"LC_ALL=C "+'md5sum \'/proc/'+pid+'/exe\' 2>/dev/null');
        item = pregmatch(pattern:'^([a-zA-Z0-9]{32}) ', string: exe_md5sum);
        if(!isnull(item)) md5s[pid] = item[1];
      }

      cmdline_pure = info_send_cmd(cmd:"LC_ALL=C "+'cat \'/proc/'+pid+'/cmdline\' 2>/dev/null');
      cmdline = join(split(cmdline_pure, sep:'\x00', keep:FALSE), sep:' ');
      cmdline_enc = base64(str:cmdline_pure);
    }
    else
    {
      exe = cmdline = '';
    }
    if (strlen(exe) == 0) exe = chomp(v[7]);
    if (strlen(exe) == 0) continue;

    localaddrs[k] = v[2];
    exes[k] = exe;
    if (pid > 0) pids[k] = pid;
    if (strlen(cmdline) > 0) cmdlines[k] = cmdline;
    if (strlen(cmdline_enc) > 0) cmdlines_enc[k] = cmdline_enc;
  }
}
# Suggested by Bernhard Thaler
#
# http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg21264632
else if ("AIX" >< uname)
{
  netstat_cmd = "netstat -Aan";
  buf = info_send_cmd(cmd:"LC_ALL=C "+netstat_cmd);
  if (strlen(buf) == 0)
  {
    errmsg = ssh_cmd_error();
    if (errmsg) errmsg ='for the following reason :\n\n' + errmsg + '\n\n';
    else errmsg = 'for an unknown reason. ';
    errmsg = "Failed to run '" + netstat_cmd + "' " + errmsg;
    if (info_t == INFO_SSH) ssh_close_connection();
    exit(1, errmsg);
  }
  set_kb_item(name:"Host/netstat_Aan", value:buf);

  foreach line (split(buf, keep:FALSE))
  {
    v = pregmatch(string:line, pattern:'^(f[a-f0-9]{15})[ \t]+((tcp|udp)[46]?)[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+(\\*|[0-9]+\\.[0-9.]+\\.[0-9]+\\.[0-9]+)\\.([0-9]+)[ \t]+(\\*|[0-9]+\\.[0-9.]+\\.[0-9]+\\.[0-9]+)\\.[0-9*]+([ \t]+LISTEN)?$');
    if (isnull(v)) continue;

    port = int(v[5]);
    if (port < 0 || port > 65535) continue;

    proto = tolower(v[3]);
    if (proto != "tcp" && proto != "udp") continue;

    pcbaddr = v[1];

    exe = cmdline = '';

    cmd = "rmsock " + pcbaddr + " ";
    if (proto == "tcp") cmd += "tcpcb";
    else cmd += "inpcb";

    buf = info_send_cmd(cmd:"LC_ALL=C "+cmd + ' 2>/dev/null');
    if (strlen(buf) > 0)
    {
      buf = chomp(buf);
      v2 = pregmatch(string:buf, pattern:"The socket [^ ]+ is being held by proccess ([0-9]+)[ \t]+\(([^)]+)\)\.");
      if (!isnull(v2))
      {
        pid = int(v2[1]);
        exe = v2[2];

        cmd = "proctree " + pid;
        buf = info_send_cmd(cmd:"LC_ALL=C "+cmd+" 2>/dev/null");
        if (strlen(buf) > 0)
        {
          foreach line (split(buf, keep:FALSE))
          {
            v2 = pregmatch(pattern:'^[ \t]*'+pid+'[ \t]+([^ \t].+)$', string:line);
            if (!isnull(v2)) cmdline = v2[1];
          }
        }
      }
      else
      {
        v2 = pregmatch(string:buf, pattern:"The socket [^ ]+ is being held by Kernel/Kernel Extension\.");
        if (!isnull(v2))
        {
          pid = "n/a";
          exe = "[kernel/kernel extension]";
        }
      }
    }
    if (strlen(exe) == 0) continue;

    k = strcat(proto, '/', port);
    if (exes[k]) continue;

    localaddrs[k] = v[4];
    exes[k] = exe;
    if (pid > 0 || pid == "n/a") pids[k] = pid;
    if (strlen(cmdline) > 0) cmdlines[k] = cmdline;
  }
}
if (max_index(keys(exes)) == 0)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, "The host does not have any listening services.");
}


found = 0;
ip = get_host_ip();

foreach k (sort(keys(exes)))
{
  v = pregmatch(pattern:"^(.+)/([0-9]+)$", string:k);
  if (isnull(v))
  {
    if (info_t == INFO_SSH) ssh_close_connection();
    exit(1, "Failed to parse protocol / port info for '"+k+"'.");
  }

  proto = v[1];
  port = v[2];

  exe = exes[k];
  localaddr = localaddrs[k];
  cmdline = cmdlines[k];
  cmdline_enc = cmdlines_enc[k];
  if (strlen(cmdline) == 0) cmdline = "n/a";
  if (strlen(cmdline_enc) == 0) cmdline_enc = "n/a";
  pid = pids[k];

  set_kb_item(name:'Host/Daemons/'+localaddr+'/'+proto+'/'+port, value:exe);

  if (
    (
      TARGET_IS_IPV6 &&
      (localaddr == "::" || localaddr == ip)
    ) ||
    (
      !TARGET_IS_IPV6 &&
      (localaddr == '0.0.0.0' || localaddr == ip || localaddr == "::" || localaddr == "*")
    )
  )
  {
    set_kb_item(name: 'Host/Listeners/'+proto+'/'+port, value:exe);
    set_kb_item(name: 'Host/Listeners/'+proto+'/'+port+'/cmdline', value:cmdline_enc);
    set_kb_item(name: 'Host/Listeners/'+proto+'/'+port+'/pid', value:pid);

    found++;

    match = pregmatch(pattern:"^(.+) \(deleted\)$", string:exe);
    if (!isnull(match)) exe = match[1];

    if (exe[0] == '/') lead_slash = '';
    else lead_slash = '/';

    if(!isnull(md5s[pid]))
      replace_kb_item(name: 'Host/DaemonMD5s' + lead_slash + exe, value:md5s[pid]);

    # this is here so we only report on listening pre-linked daemons
    if(prelinked[exe])
    {
      # whitelist
      if(exe =~ "^[0-9A-Za-z_\-./]+$")
        buf = info_send_cmd(cmd:"prelink -y " + exe + " | md5sum");

      item = pregmatch(pattern:'^([a-zA-Z0-9]{32}) ', string: buf);
      if(!isnull(item))
        replace_kb_item(name: 'Host/PrelinkedDaemons' + lead_slash + exe, value:item[1]);
      else
        replace_kb_item(name: 'Host/PrelinkedDaemons' + lead_slash + exe, value:'md5_unknown');

    }
    report = '\n  Process ID   : ' + pid +
             '\n  Executable   : ' + exe;
    if (strlen(cmdline) > 0) report += '\n  Command line : ' + cmdline;
    report += '\n';
    if (COMMAND_LINE) report = '\n  Port         : ' + port + ' (' + proto + ')' + report;

    if (report_verbosity > 0) security_note(port:port, proto:proto, extra:report);
    else security_note(port:port, proto:proto);
  }
}
if (info_t == INFO_SSH) ssh_close_connection();
if (found) set_kb_item(name:"Host/Listeners/Check", value:netstat_cmd);
