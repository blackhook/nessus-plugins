#TRUSTED 64ea8e5ab4a5311c1e664fa72caa15ffb55518bc3139aa89d10baa1117c23863053174c57015cbaccf59b1807cc39deb3619b24ce0b33faededbed5eb132f4c6e7f9d3b34684afc3556af13d97e704ab64f750dcc3ff51167d964b20e13d4ff3add8e630ca2f3fd60bd5e39559dbf30811e7f3ad0dd2db4b832f088289a592d24a9e3c50b489d3a0709e1439c9c3af770881af54c0ec0d4256b98b767f0134b43b0b6f2a9e24710c958e6517ef0e06dfeb1e413204c64facc470b6bf8735b8debb44cbf9f461747c858e2cb91bf7d5ed7becc41b3106552df0357bc8881cc5bc715776cb27d25acda165756af38293046408336ebeb60f7f8bf37c1cc72f59e2b7f2d72f1fd19c21c4f0861a04e8740bc7e57889a1b81c273966121ec5beadaf506f9ecd89eadc95ef8d84292b467e2f7b913e5af983a3dd0929cec423692925474ecbd403500678fadd2d49ca0dde490cda8d0756883ff2c01412e96898f34bd7ddd866177e78cd98081bbad98a9819d3f02cba56b460f0a5d80902d679ee5cba0fe142c91ff8234a12ee90a23e2041d86790d637d2bbcf0d86450a695f9b38d1c4c8cebcd5742804e0e15f6bc74a49f1432c79fb896e6403713e96cba5a2fa056ece078f1ca479944224d5ede82460fd2843e54df904aee4d3ce76e3dcf1648314664159dc8e54a87de538238cf82bbbb1cc6b3d3f7422ca268e7574f85d08
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25202);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/23");

 script_name(english:"Enumerate IPv6 Interfaces via SSH");
 script_summary(english:"Uses the result of 'ifconfig -a' or 'ip addr show'.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate the IPv6 interfaces on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the network interfaces configured with
IPv6 addresses by connecting to the remote host via SSH using the
supplied credentials.");
 script_set_attribute(attribute:"solution", value:
"Disable IPv6 if you are not actually using it. Otherwise, disable any
unused IPv6 interfaces.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");

 script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_ports("Host/ifconfig", "Host/netstat-ianf-inet6", "Secret/Host/Cisco/Config/show_running-config");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include("cisco_host_ip_enum.inc");

uname = get_kb_item("Host/uname");
is_cisco = !isnull(get_kb_list("Host/Cisco/*"));
if(empty_or_null(uname) && !is_cisco) exit(1, 'Neither Host/uname nor any Host/Cisco/* KB item is set');

ifaces = NULL;
dev = NULL;
dev_ip_count = make_array();

# HP-UX
if ('HP-UX' >< uname)
{
  netstat = get_kb_item_or_exit("Host/netstat-ianf-inet6");
  lines = split(netstat, keep:FALSE);
  netstat_pat = "^([^\s]+)\s+[0-9]+\s+([0-9a-fA-F:%]+)(\/[0-9]+)?(?:\s+[0-9]+)+";
  foreach line (lines)
  {
    match = pregmatch(pattern:netstat_pat, string:line);
    if (isnull(match)) continue; # next

    iface_name = match[1];
    ip_addr = match[2]; #ipv6

    if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
    else dev_ip_count[iface_name]++;

    ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name, ')\n');

    set_kb_item(name:"Host/iface/id", value:iface_name);
    set_kb_item(name:"Host/iface/"+iface_name+"/ipv6", value:ip_addr);
    set_kb_item(name:"Host/ifconfig/IP6Addrs", value: ip_addr);
  }
}
else if(is_cisco)
{
  ip_array = cisco_host_ip_enum::get_ip_array(v6:TRUE);
  for(iface_name in ip_array)
  {
    foreach(ip_addr in ip_array[iface_name])
    {
      if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
      else dev_ip_count[iface_name]++;

      ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name + ')\n');

      set_kb_item(name:"Host/iface/id", value:iface_name);
      set_kb_item(name:"Host/iface/"+iface_name+"/ipv6", value:ip_addr);
      set_kb_item(name:"Host/ifconfig/IP6Addrs", value: ip_addr);
    }
  }
}
else
{
  ifconfig = get_kb_item_or_exit("Host/ifconfig");
  inet6 = egrep(pattern:"inet6", string:ifconfig);
  if ( isnull(inet6) ) exit(0, 'No IPv6 addresses found.');

  lines = split(ifconfig, keep:FALSE);
  ifconfig_regex = "^(\d+: )?([a-z\-]+[\-a-z0-9]+(:[0-9]+)?)[: ].*";
  foreach line ( lines )
  {
    if ( line =~ ifconfig_regex )
    {
      dev = ereg_replace(pattern:ifconfig_regex, replace:"\2", string:line);
      if ( dev == line ) dev = NULL;
      if (!isnull(dev)) dev_ip_count[dev] = 0;
    }

    if  ( "inet6" >< line )
    {
      addr = ereg_replace(pattern:".*inet6( addr:)? ([0-9a-f:]*).*", string:line, replace:"\2");
      if ( !empty_or_null(addr) && addr != line )
      {
        ifaces += ' - ' + addr;
        set_kb_item(name: "Host/ifconfig/IP6Addrs", value: addr);
        if ( !empty_or_null(dev) )
        {
          ifaces += ' (on interface ' + dev + ')';
          dev_ip_count[dev]++;
          # for reporting
          set_kb_item(name:"Host/iface/"+dev+"/ipv6", value: addr);
          set_kb_item(name:"Host/iface/id", value:dev);
        }
        ifaces += '\n';
      }
    }
  }
}

foreach dev (keys(dev_ip_count))
{
  aliased = dev_ip_count[dev] > 1;
  if (aliased)
    set_kb_item(name:"Host/iface/"+dev+"/aliased", value:TRUE);
}

if ( strlen(ifaces) )
{
 security_note(port:0, extra:'\nThe following IPv6 interfaces are set on the remote host :\n\n' + ifaces);
}
else exit(1, 'Unable to parse any IPv6 addresses.');
