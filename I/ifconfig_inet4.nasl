#TRUSTED 0494a1acdbdf91ddb800ae4ea5896317f97de73700a6d011dfa5762d6aae77804ac2665fbc16a928d9cb778ffad385fe52e46af89c320ec3cc38269656f65ab78b9864205bacf94646d1530cfe94cda138e3099bce393cd50d79e2ced4abd116daba9920e9ff6c2a63be4811d7662fc1affc39886db8ad4b469701f018a3cc851f2d1ba2733682c3175345584eae34e9f0f1aa2abf8f71b05b5699d1ff8ba28b65d25f95103e93199c63d56fb39d8cca9067ed571e12ae4a639b57b0139bc3b4ae211724c5ed99b17926609eb8339c7dfcba1e885725cb7a5c9566510ff79b739714626e39a24a948cd0e21677b9bcff6f471b65e0514c3ffc4edf49009135d06cb5234b5703b4de98abeb3367c29d27d442af6a7a5f66cbadd620328459fe1fc07e8254a6fab1df7c2e943a688c4076b60ddcd6aedcd58a5f370ed6da74833cd1d1c3cc7feefd49ea0f419712134aaf5aec44d65896a518d79c5130a9cb7e10c312974afd45c4a226c0179ba5e70be7e5a39f844cf033ccabdf64589ea04dee995ddde9afc482a9b0432b281097d938bd243fed58cdd671adefa8dedf799871a08f4c8a30f35fc51f8d6f98c22406218e2b5ba7fcc3ca253a075b92e65c28ed60d20d2cc12b47bbadf475e1d86591fecbb63b79e93978ebe52e365ce7710f8a1662a3cfb4a7b7207079343abd90a2acaa00c942afd83bfd26a56a87b68d6911
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25203);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/23");

 script_name(english:"Enumerate IPv4 Interfaces via SSH");
 script_summary(english:"Uses the result of 'ifconfig -a' or 'ip addr show'.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate the IPv4 interfaces on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the network interfaces configured with
IPv4 addresses by connecting to the remote host via SSH using the
supplied credentials.");
 script_set_attribute(attribute:"solution", value:
"Disable any unused IPv4 interfaces.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");

 script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_ports("Host/ifconfig", "Host/netstat-ian", "Secret/Host/Cisco/Config/show_running-config");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("cisco_host_ip_enum.inc");

uname = get_kb_item("Host/uname");
is_cisco = !isnull(get_kb_list("Host/Cisco/*"));
if(empty_or_null(uname) && !is_cisco) exit(1, 'Neither Host/uname nor any Host/Cisco/* KB item is set');

ifaces = NULL;
dev    = NULL;
dev_ip_count = make_array();

# HP-UX
if ('HP-UX' >< uname)
{
  netstat = get_kb_item_or_exit("Host/netstat-ian");
  lines = split(netstat, keep:FALSE);
  netstat_pat = "^([^\s]+)\s+[0-9]+\s+[^\s]+\s+([0-9.]+)(?:\s+[0-9]+)+";
  foreach line (lines)
  {
    match = pregmatch(pattern:netstat_pat, string:line);
    if (isnull(match)) continue; # next

    iface_name = match[1];
    ip_addr = match[2];

    if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
    else dev_ip_count[iface_name]++;

    ifaces += strcat(' - ',  ip_addr, ' (on interface ', iface_name, ')\n');

    set_kb_item(name:"Host/iface/id", value:iface_name);
    set_kb_item(name:"Host/iface/"+iface_name+"/ipv4", value:ip_addr);
    set_kb_item(name:"Host/ifconfig/IP4Addrs", value: ip_addr);
  }

  # look for virtual interfaces
  # e.g. eth0:1
  foreach iface_name (keys(dev_ip_count))
  {
    match = pregmatch(pattern:"((\S+):\S+)", string:iface_name);
    if (!isnull(match))
    {
      # eth0:1 (virtual)
      set_kb_item(name:"Host/iface/"+match[1]+"/virtual", value:TRUE);

      # eth0 (aliased)
      set_kb_item(name:"Host/iface/"+match[2]+"/aliased", value:TRUE);
    }
  }
}
else if(is_cisco)
{
  ip_array = cisco_host_ip_enum::get_ip_array();
  for(iface_name in ip_array)
  {
    foreach(ip_addr in ip_array[iface_name])
    {
      if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
      else dev_ip_count[iface_name]++;

      ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name, ')\n');

      set_kb_item(name:"Host/iface/id", value:iface_name);
      set_kb_item(name:"Host/iface/"+iface_name+"/ipv4", value:ip_addr);
      set_kb_item(name:"Host/ifconfig/IP4Addrs", value: ip_addr);
    }
  }
}
else
{
  ifconfig = get_kb_item_or_exit("Host/ifconfig");
  inet = egrep(pattern:"inet[^6]", string:ifconfig);
  if ( isnull(inet) ) exit(0, 'No IPv4 addresses found.');

  lines = split(ifconfig, keep:FALSE);

  ifconfig_regex = "^(\d+: )?([a-z\-]+[\-a-z0-9]+(:[0-9]+)?)[: ].*";
  foreach line ( lines )
  {
    if ( line =~ ifconfig_regex )
    {
      dev = ereg_replace(pattern:ifconfig_regex, replace:"\2", string:line);
      if ( dev == line )
        dev = NULL;
      # ip count
      if (!isnull(dev)) dev_ip_count[dev] = 0;
    }

    if  ( "inet" >< line && "inet6" >!< line )
    {
      addr = ereg_replace(pattern:".*inet( addr:)? ?([0-9.]+).*", string:line, replace:"\2");
      if ( !empty_or_null(addr) && addr != line )
      {
        ifaces += ' - ' + addr;
        set_kb_item(name:"Host/ifconfig/IP4Addrs", value: addr);

        if ( !empty_or_null(dev) )
        {
          ifaces += ' (on interface ' + dev + ')';
          dev_ip_count[dev]++;
          # for reporting
          set_kb_item(name:"Host/iface/"+dev+"/ipv4", value: addr);
          set_kb_item(name:"Host/iface/id", value:dev);
        }

        ifaces += '\n';
      }
    }
  }
}

# if a device has more than one ip, it is aliased
foreach dev (keys(dev_ip_count))
{
  aliased = dev_ip_count[dev] > 1;
  if (aliased)
    set_kb_item(name:"Host/iface/"+dev+"/aliased", value:TRUE);
}

if ( strlen(ifaces) )
{
 security_note(port:0, extra:'\nThe following IPv4 addresses are set on the remote host :\n\n' + ifaces);
}
else exit(1, 'Unable to parse any IPv4 addresses.');
