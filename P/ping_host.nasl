#TRUSTED 338b2792d480dbd93e5c94820dcc91efc043e4f527e85abbb02d569401466dad7e7c5e79c0018617c3ba9966450e7444d30cd7e9892f5470f1ce849ca97000db7b9d12ab785b263fe82d7e68edd1357b873d2145a10510fcbb37362ef2f1c241c4ef1f6876544a3abd1dab5332b32fa359da2e128e102c10d0887d99b2339a8e1d3900f555f1131e346e2cb7bcb3bdb580f286084dc38b6689f7e7f9896631710c5540d8de51b646acae72a64e6aed682228cf6868fbf49751387153040e09a675ac3fdd0b0b1918a51e293913fe1c78c3cf35e180a965f109b4ed45b560a44a8775b2759bdc27f92ba7a1069b89bb0eba0c055f0ae5bef0b9df7be744ca93664fecec873ab19d53c8095a7079e34508b8eddfd4b187a6de3260447ad27e96f81988b47eadd619e9b748b56042d5a1511c84cbfdeea40501abe82e4dc56ec20ae20269bb042bb203ff5bffb1896338b170aae996f8a8ef6a08dffb7c357b5a8541747641c36e468e8577ecc539df15bc39ad0deefb1d96012a78a794a0fbca83a7379a632e9280f4afced06725818a8a0890a93e7acd2d5e7a1d05c2c3ff75967adb3d926921222b5dab54cdfad363489cd6eb2b8c04bff636f303753d3306cef03f19d0a9db7f762b6b58ac84977c9e81a33e0dfb461f92dbd56c9739c2ce52c1dc2b3d9274bd91261a169defdf169ffb308383321548fc947482037f07b382
#TRUST-RSA-SHA256 a170c9d62df39c0d9ad7d243ae2a315784335b8fddeae5bb15eab792721fff101b7d005ebcd66d66df077533e00483a34182d768ba88f4bc0a17d9c309477d96fd23db020b84241e9f1f78fd3f9af62dc0ad16b3819396c11b73a7747a671e95acaa5e96580413a41e63ecb6a444e8efbe34792e70d5e2354857b096afb8f7c2ad37c4317fb05d02a6f8190be125bf943f07fbacaa17d3f2f0853e540397d6bb34945cc78dbb40925f719df5b7fa7c7a9489ba64e7de445a0d6ca2497f8306d7e1551d18b27e6504b3ddd2cebf2f092af50620509db5e22fb2e683c26ac3568bded6e826b40cafed75d29c48ac38071fe20feda085357c12a918c079746e95f0cf7b21e941c14a0ff189b9e92776e19e81d97c97a5b8f6d236896a2ea45f14755c36d6e3861a69e34aba36c75d1220599c8406b7b4433dd62d3928ebc514d39a9deecd81b11dcb040cff85318145569235056f80de1140a7a604d5102f50760779b122f723b19e8604262d2dc77764af2e4ce30295c2d40413319d098e59c508b623f3ecf9640a7d81a65fe03ffffa1bcc0386983fb7c806b23d9324198e4664b8d81fba7baeb860161c16afbb0e5deec47f08044816fe100cd8fc5a2e18edf5defc1cc645e124c265c8dfe9da68c39ecd3bbf5187f26b3b4369c623032e7d86f0fa25b4db5737eaf9390f2a9620096185af6c0c3c4a3f2e506d1f2077630cda
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
include("ping_host4.inc");

defportlist= "built-in";

if(description)
{
 script_id(10180);
 script_version("2.36");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/28");

 script_name(english:"Ping the remote host");
 script_summary(english:"Pings the remote host.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to identify the status of the remote host (alive or
dead).");
 script_set_attribute(attribute:"description", value:
"Nessus was able to determine if the remote host is alive using one or
more of the following ping types :

  - An ARP ping, provided the host is on the local subnet
    and Nessus is running over Ethernet.

  - An ICMP ping.

  - A TCP ping, in which the plugin sends to the remote host
    a packet with the flag SYN, and the host will reply with
    a RST or a SYN/ACK.

  - A UDP ping (e.g., DNS, RPC, and NTP)." );
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/24");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_SCANNER);

 script_copyright(english:"This script is Copyright (C) 1999-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Port scanners");

 script_add_preference(name:"TCP ping destination port(s) :",
                       type:"entry", value:defportlist);
 if ( defined_func("inject_packet") )
  script_add_preference(name:"Do an ARP ping",
                       type:"checkbox", value:"yes");

 script_add_preference(name:"Do a TCP ping", 
                      type:"checkbox", value:"yes");
 script_add_preference(name:"Do an ICMP ping",
                      type:"checkbox", value:"yes");

 script_add_preference(name:"Number of retries (ICMP) :", type:"entry", value:"2");	
 script_add_preference(name:"Do an applicative UDP ping (DNS,RPC...)",
                      type:"checkbox", value:"no");

 script_add_preference(name:"Make the dead hosts appear in the report",
                       type:"checkbox", value:"no");

 script_add_preference(name:"Log live hosts in the report",
                        type:"checkbox", value:"no");

 script_add_preference(name:"Test the local Nessus host", type:"checkbox", value:"yes");
 script_add_preference(name:"Fast network discovery", type:"checkbox", value:"no");
 script_add_preference(name:"Interpret ICMP unreach from gateway", type:"checkbox", value:"no");

 exit(0);
}

#
# The script code starts here
#
global_var log_live, do_arp, test, show_dead, did_arp;

include("global_settings.inc");
include("raw.inc");
include("misc_func.inc");

var tcp_opt = raw_string(
	0x02, 0x04, 0x05, 0xB4,	# Maximum segment size = 1460
	0x01,			# NOP
	0x01,			# NOP
	0x04, 0x02
  );		# SACK permitted

# 
# Utilities
#


function mkipaddr()
{
 var ip, hostIpNoScope;
 var str, r;

 ip = _FCT_ANON_ARGS[0];
 str = split(ip, sep:'.', keep:FALSE);
 return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3])); 
}


function mk_icmp_pkt(id)
{
  var hostIpNoScope;

  if ( NASL_LEVEL < 4000 )
  {
    if ( TARGET_IS_IPV6 ) return NULL;
    var ip,icmp;
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0, ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40, ip_src:compat::this_host());
    icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq: 1, icmp_id:1);
    return make_list(icmp, "ip and src host " + get_host_ip());
  }
  else
  {
    if ( TARGET_IS_IPV6 )
    {
      # Commenting out due to compilation erros on older versions
      #if (defined_func('get_host_ip_ex'))
      #{
      #  r = make_list(mkpacket(ip6(), icmp(ih_type:128, ih_code:0, ih_seq:id)), "ip6 and src host " + get_host_ip_ex(options: {"flags": IPFMT_IP6_NO_SCOPE}));
      #}
      #else
      #{
        hostIpNoScope = ereg_replace(string:get_host_ip(), pattern:"(.*)(%.*)", replace:"\1");
        r = make_list(mkpacket(ip6(), icmp(ih_type:128, ih_code:0, ih_seq:id)), "ip6 and src host " + hostIpNoScope);
      #}

      return r;
    }
    else
    {
      return make_list(mkpacket(ip(), icmp(ih_type:8, ih_code:0, ih_seq:id)),  "ip and src host " + get_host_ip());
    }
  }
}


#
# Global Initialisation
#
if(isnull(get_kb_item("/tmp_start_time")))
  replace_kb_item(name: "/tmp/start_time", value: unixtime());
do_arp = script_get_preference("Do an ARP ping");
if(!do_arp)do_arp = "yes";

do_tcp = script_get_preference("Do a TCP ping");
if(!do_tcp)do_tcp = "yes";

do_icmp = script_get_preference("Do an ICMP ping");
if(!do_icmp)do_icmp = "yes"; 

do_udp = script_get_preference("Do an applicative UDP ping (DNS,RPC...)");
if (! do_udp) do_udp = "no";

var fast_network_discovery = script_get_preference("Fast network discovery");
if ( !fast_network_discovery) fast_network_discovery = "no";


interpret_icmp_unreach = script_get_preference("Interpret ICMP unreach from gateway");
if ( ! interpret_icmp_unreach ) interpret_icmp_unreach = "no";


test = 0;


show_dead = script_get_preference("Make the dead hosts appear in the report");
log_live = script_get_preference("Log live hosts in the report");
if ( "yes" >< show_dead ) set_kb_item(name: '/tmp/ping/show_dead', value:TRUE);
if ( "yes" >< log_live ) set_kb_item(name: '/tmp/ping/log_live', value:TRUE);



var scan_local = script_get_preference("Test the local Nessus host");
if ( scan_local == "no" && islocalhost() ) 
{
  set_kb_item(name:"Host/ping_failed", value:TRUE);
  var failreason = "The target is localhost, and 'Test the local Nessus host' is set to 'no' in the scan policy.";
  replace_kb_item(name:'Host/ping_failure_reason', value:failreason);
  exit(0);
}


#
# Fortinet Firewalls act as an AV gateway. They do that
# by acting as a man-in-the-middle between the connection
# and the recipient. If there is NO recipient, then sending
# data to one of the filtered ports will result in a timeout.
#
# By default, Fortinet listens on port 21,25,80,110 and 143.
#
#
function check_fortinet_av_gateway()
{
  var soc, now, r, report, failreason;

  if ( did_arp ) return FALSE;
  if ( fast_network_discovery == "yes" ) return FALSE;
  soc = open_sock_tcp(25, timeout:3);
  if ( !soc ) return 0;
  now = unixtime();
  r = recv_line(socket:soc, length:1024, timeout:5);
  if ( r || unixtime() - now < 4 ) return 0;
  close(soc);


  soc = open_sock_tcp(110, timeout:3);
  if ( ! soc ) return 0;
  now = unixtime();
  r = recv_line(socket:soc, length:1024, timeout:5);
  if ( r || unixtime() - now < 4 ) return 0;
  close(soc);

  soc = open_sock_tcp(143, timeout:3);
  if ( ! soc ) return 0;
  now = unixtime();
  r = recv_line(socket:soc, length:1024, timeout:5);
  if ( r || unixtime() - now < 4 ) return 0;
  close(soc);

  # ?
  soc = open_sock_tcp(80, timeout:3);
  if ( ! soc ) return 0;
  send(socket:soc, data:http_get(item:"/", port:80));
  now = unixtime();
  r = recv_line(socket:soc, length:1024, timeout:5);
  if ( r || unixtime() - now < 4 ) return 0;
  close(soc);

  report = "
  The remote host seems to be a Fortinet firewall, or some sort of 
  man-in-the-middle device, so Nessus will not scan it. If you want to 
  force a scan of this host, disable the 'ping' plugin and restart a 
  scan.";

  failreason = "The remote host seems to be a Fortinet firewall, or some sort of man-in-the-middle device.";
  replace_kb_item(name:'Host/ping_failure_reason', value:failreason);
  return 1;
}



function check_riverhead_and_consorts()
{
  var ip, tcpip, i, is, flags, j, r, report, failreason;

  if ( TARGET_IS_IPV6 ) return 0;
  if ( did_arp ) return 0;
  if ( fast_network_discovery == "yes") return 0;

    ip = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_id : rand() % 65535,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 175,
                        ip_off : 0,
      ip_src : compat::this_host());



  is = make_list();
  for ( i = 0 ; i < 10 ; i ++ )
  {
    is = make_list(is, i);
  }
  for ( i = 1 ; i < 5 ; i++ )
  {
    is = make_list(is, (rand() % 1024) + 10);
  }

  foreach i (is)
  {
    tcpip = forge_tcp_packet(ip       : ip,
                              th_sport : 63000 + i,
                              th_dport : 60000 + i,
                              th_flags : TH_SYN,
                              th_seq   : rand(),
                              th_ack   : 0,
                              th_x2    : 0,
                              th_off   : 5,
                              th_win   : 512,
            data:	tcp_opt);

    for ( j = 0 ; j < 3 ; j ++ )
    {
      r = send_packet(tcpip, pcap_active:TRUE, pcap_filter:"src host " + get_host_ip()+ " and dst host " + compat::this_host() + " and src port " + int(60000 + i) + " and dst port " + int(63000 + i ), pcap_timeout:1);
      if ( r ) break;
    }
    if ( ! r ) return 0;
    flags = get_tcp_element(tcp:r, element:"th_flags");
    if( flags != (TH_SYN|TH_ACK) ) return 0;
  }

  report = "
  The remote host seems to be a RiverHead device, or some sort of decoy 
  (it returns a SYN|ACK for any port), so Nessus will not scan it. If 
  you want to force a scan of this host, disable the 'ping' plugin and 
  restart a scan.";

  failreason = "The remote host seems to be a RiverHead device, or some sort of decoy that returns a SYN|ACK for any port";
  replace_kb_item(name:'Host/ping_failure_reason', value:failreason);

  return 1;
}



function check_netware()
{
  var ports, then, port, soc, num_sockets, num_ready, ready, failreason;
  var report, banner;

  if ( NASL_LEVEL < 3000 ) return 0;
  if (  get_kb_item("Scan/Do_Scan_Novell") ) return 0;

  report = "
  The remote host appears to be running Novell Netware.  This operating
  system has a history of crashing or otherwise being adversely affected
  by scans.  As a result, the scan has been disabled against this host. 

  http://www.nessus.org/u?08f07636
  http://www.nessus.org/u?87d03f4c

  If you want to scan the remote host enable the option 'Scan Novell
  Netware hosts' in the Nessus client and re-scan it. ";

  ports = make_list(80, 81, 8009);
  then = unixtime();
  foreach port ( ports )
    soc[port] = open_sock_tcp(port, nonblocking:TRUE);

  while ( TRUE )
  {
    num_sockets = 0;
    num_ready   = 0;
    foreach port ( ports )
    {
      if ( soc[port] )
      {
        num_sockets ++;
        if ( (ready = socket_ready(soc[port])) != 0 ) 
        {
          num_ready ++;
          if ( ready > 0 )
          {
            send(socket:soc[port], data:'GET / HTTP/1.0\r\n\r\n');
            banner = recv(socket:soc[port], length:4096);
          }
          else
          {
            banner = NULL;
          }
          close(soc[port]);
          soc[port] = 0;
          if ( banner && egrep(pattern:"Server: (NetWare HTTP Stack|Apache(/[^ ]*)? \(NETWARE\))", string:banner) )
          {
            failreason = "The remote host appears to be running Novell Netware, which is adversely affected by scans";
            replace_kb_item(name:'Host/ping_failure_reason', value:failreason);

            return 1;
          }
        }
      }
    }

    if ( num_sockets == 0 ) return 0;
    if ( num_ready   == 0 && (unixtime() - then) >= 3 ) return 0;
    usleep(50000);
  }
  return 0;
}



function log_live(rtt, cause)
{
  var reason, host_ip;
  #
  # Let's make sure the remote host is not a riverhead or one of those annoying
  # devices replying on every port
  #
  if ( !islocalhost() && 
      (check_fortinet_av_gateway() || 
      check_riverhead_and_consorts() ||
      check_netware())
      )
  {
    reason = get_kb_item('Host/ping_failure_reason');
    if (!empty_or_null(reason))
      log_dead(reason);
  }
  else
  {
    host_ip = get_host_ip();
    report_xml_tag(tag:"host-ip", value:host_ip);
    replace_kb_item(name:"Host/Tags/report/host-ip", value:host_ip);
  }

  #debug_print(get_host_ip(), " is up\n");
  if ("yes" >< log_live)
  {
    security_note(port:0, extra:'The remote host is up\n' + cause);
  }
  if (rtt) {
    set_kb_item(name: "/tmp/ping/RTT", value: rtt);
    set_kb_item(name: "ping_host/RTT", value: rtt);
  }
  #debug_print('RTT=', rtt, 'us\n');
  exit(0);
}


function log_dead()
{
  var reason, host_ip;
  reason = _FCT_ANON_ARGS[0];
  #debug_print(get_host_ip(), " is dead\n");
  if('yes' >< show_dead)
  security_note(port:0, extra:'The remote host (' + get_host_ip() + ') is considered as dead - not scanning\n' + reason);

  # Mark the IP in the .nessus file anyways [SC]
  host_ip = get_host_ip();
  report_xml_tag(tag:"host-ip", value:host_ip);
  replace_kb_item(name:"Host/Tags/report/host-ip", value:host_ip);

  set_kb_item(name:"Host/ping_failed", value:TRUE);
  exit(0);
}


function send_arp_ping()
{
  var broadcast, macaddr, ethernet, arp, r, i, srcip, dstmac, t1, t2;
  var ip;

  ip = _FCT_ANON_ARGS[0];

  broadcast = crap(data:raw_string(0xff), length:6);
  macaddr   = get_local_mac_addr();

  if ( !macaddr ) return NULL ;  # Not an ethernet interface

  arp       = mkword(0x0806); 


  ethernet = broadcast + macaddr + arp;

  arp      = ethernet +              			# Ethernet
            mkword(0x0001) +        			# Hardware Type
            mkword(0x0800) +        			# Protocol Type
            mkbyte(0x06)   +        			# Hardware Size
            mkbyte(0x04)   +        			# Protocol Size
            mkword(0x0001) +        			# Opcode (Request)
            macaddr        +        			# Sender mac addr
            mkipaddr(compat::this_host()) + 			# Sender IP addr
            crap(data:raw_string(0), length:6) + 	# Target Mac Addr
            mkipaddr(ip);

  for ( i = 0 ; i < 3 ; i ++ )
  {
    r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + ip, timeout:1);
    if ( r && strlen(r) > 31 ) 
      return r;
  }

  r = send_arp_ping_alt(arp:arp, ip:ip, macaddr:macaddr);
  if (!isnull(r)) return r;

  return NULL;
}


##
# Alternative for when the PCAP filter in arp_ping() fails.
#
# @param [arp:string] arp broadcast packet
# @param [ip:string] target IP address
# @param [macaddr:string] local MAC address sending from
#
# @remark This was created for Windows EC2 instances where the filtering is broken.
#
# @return ARP response if found or NULL if not found or an error occurred
##
function send_arp_ping_alt(arp, ip, macaddr)
{
  var macaddr_with_colons;
  var r, i, bpf, bpfres;

  macaddr = hexstr(macaddr);
  if (isnull(macaddr)) return NULL;

  # Add colons to macaddr for PCAP filter
  macaddr_with_colons = ereg_replace(string:macaddr, pattern:"([0-9a-f]{2}(?=.))", replace:"\1:", icase:TRUE);

  # Start capturing
  bpf = bpf_open("arp and ether dst " + macaddr_with_colons);

  r = inject_packet(packet:arp, filter:"arp and ether dst " + macaddr_with_colons, timeout:1);

  # No ARP reply packets seen
  if (isnull(r))
  {
    bpf_close(bpf);
    return NULL;
  }

  # Validate initial ARP response
  if (
    substr_at_offset(str:r, blob:'\x00\x02', offset:20) && # reply opcode (2)
    substr_at_offset(str:r, blob:mkipaddr(ip), offset:28)  # sender IP address
  )
  {
    bpf_close(bpf);
    return r;
  }

  if (isnull(bpf)) return NULL;

  # Examine the 30 next ARP reply packets
  for ( i = 0 ; i < 30 ; i ++ )
  {
    bpfres = bpf_next(bpf:bpf, timeout:0);
    if (isnull(bpfres)) break;

    if (
      substr_at_offset(str:bpfres, blob:'\x00\x02', offset:20) && # reply opcode (2)
      substr_at_offset(str:bpfres, blob:mkipaddr(ip), offset:28)  # sender IP address
    )
    {
      bpf_close(bpf);
      return bpfres;
    }
  }
  bpf_close(bpf);
  return NULL;
}

 
##
# ARP ping - send and process
#
# @return FALSE if ARP ping failed
#         NULL  if prereqs failed or an error occurred
#
# @remark This function will exit via log_live() if the ARP ping was successful.
##
function arp_ping()
{
  var t1, t2, dstmac;
  var rand_mac;
  var r, srcip;

  if ( ! defined_func("inject_packet") ) return NULL;
  if ( ! islocalnet()  || islocalhost() ) return NULL;
  if ( get_local_mac_addr() == NULL ) return NULL;

  t1 = gettimeofday();
  r = send_arp_ping(get_host_ip());
  t2 = gettimeofday();

  if ( r && strlen(r) > 31 ) 
  {
    srcip = substr(r, 28, 31);
    if ( srcip == mkipaddr(get_host_ip() ) )
    {
      dstmac = substr(r, 6, 11);
      # Make sure there's no arp proxy on the local subnet
      if ( fast_network_discovery != "yes" )
      {
      r = send_arp_ping("169.254." + rand()%254 + "." + rand()%254);
          if ( r && substr(r, 6, 11) == dstmac ) return NULL;
      }
      dstmac = hexstr(dstmac[0]) + ":" +
              hexstr(dstmac[1]) + ":" +
              hexstr(dstmac[2]) + ":" +
              hexstr(dstmac[3]) + ":" +
              hexstr(dstmac[4]) + ":" +
              hexstr(dstmac[5]);

      set_kb_item(name:"ARP/mac_addr", value:dstmac);
      did_arp = TRUE;
      set_kb_item(name: "/tmp/ping/ARP", value: TRUE);
      log_live(rtt: difftime2(t1: t1, t2: t2), cause:'The host replied to an ARP who-is query.\nHardware address : ' + dstmac);
      exit(0);
    }
  }

  log_dead("The remote host ('" + get_host_ip() + "') is on the local network and failed to reply to an ARP who-is query.");
  exit(0);
}

function can_use_new_engine()
{
  # Nessus 4.4 contains a fix for a slow bpf_next();
  if ( NASL_LEVEL >= 4400 ) UseBpfNextWorkaround = FALSE;
  else UseBpfNextWorkaround = TRUE;

  if ( defined_func("bpf_open") ) return TRUE;

  return FALSE;
}

if(islocalhost()) {
  log_live(rtt: 0, cause:"The host is the local scanner.");
  exit(0);
}

var host_ip;
# Set the IP in the .nessus file for T.sc
if ('yes' >< show_dead)
{
  host_ip = get_host_ip();
  report_xml_tag(tag:'host-ip', value:host_ip);
  replace_kb_item(name:'Host/Tags/report/host-ip', value:host_ip);
}

#do_arp = "no"; do_tcp = "yes"; do_icmp = "no"; do_udp = "no"; # TEST

###
if ('yes' >< do_arp && islocalnet() && !TARGET_IS_IPV6 )
{
  # If the remote is on the local subnet and we are running over ethernet, and 
  # if arp fails, then arp_ping() will exit and mark the remote host as dead
  # (ie: it overrides the other tests)
  arp_ping();
}


meth_tried = NULL;
var id, icmp, t1, t2, rep, hl, type, code, id2, rtt;
if ( can_use_new_engine() )
{
  if ( "yes" >< do_udp || "yes" >< do_icmp )
  {
    LinkLayer = link_layer();
    if ( isnull(LinkLayer)  ) 
    {
      if ( islocalnet() ) log_dead('It was not possible to find how to send packets to the remote host (ARP failed)');
      else log_dead('Nessus can not forge packets over the network interface used to communicate with the remote host');
    }
  }
  var p = script_get_preference("TCP ping destination port(s) :");
  var res = ping_host4(tcp_ports:p);
  if ( !isnull(res) ) log_live(rtt: res[1], cause:res[0]);
  else if ( "yes" >< do_tcp || "yes" >< do_udp || "yes" >< do_icmp ) test = 1;
}
else  # Nessus <= 3.0
{
  ####
  if("yes" >< do_tcp)
  {
    test = test + 1;
    p = script_get_preference("TCP ping destination port(s) :");
    if (!p) p = defportlist;
    if ("extended" >< p)
    {
      p = ereg_replace(string: p, pattern: "(^|;)extended(;|$)", 
        replace: "\1built-in;110;113;143;264;389;1454;1723;3389\2");    
    }

    if ( TARGET_IS_IPV6 ) p = "built-in";

    #debug_print("TCP ports=",p,"\n");
    # Change wrong delimiters
    p = ereg_replace(string: p, pattern: '[ ,]+', replace: ';');

    foreach var dport (split(p, sep: ';', keep: 0))
    {
      t1 = gettimeofday();
      if (dport == "built-in")
      {
        if (tcp_ping())
        {
          t2 = gettimeofday();
          #debug_print('Host answered to TCP SYN (built-in port list)\n');
          log_live(rtt: difftime2(t1: t1, t2: t2), cause:"The remote host replied to a TCP SYN packet (built-in port list).");
        }
      }
      else
      {
        if(tcp_ping(port:dport))
        {
          t2 = gettimeofday();
          # debug_print('Host answered to TCP SYN on port ', dport, '\n');
          set_kb_item(name: '/tmp/ping/TCP', value: dport);
          log_live(rtt: difftime2(t1: t1, t2: t2), cause:"The remote host replied to a TCP SYN packet on port " + dport + ".");
        }
      }
    }
    meth_tried += '- TCP ping\n';
  }

  ####

  if ('yes' >< do_icmp)
  {
    src = compat::this_host();
    dst = get_host_ip();
    retry = script_get_preference("Number of retries (ICMP) :");
    retry = int(retry);
    alive = 0;
    if(retry <= 0) retry = 2;	# default

    #debug_print("ICMP retry count=", retry, "\n");
    var j = 0;
    test = test + 1;
    icmpid = rand() % 0xFFFF;
    var filter = "icmp and src host " + get_host_ip();
    while(j < retry)
    {
      id = 1235 +j;
      icmp = mk_icmp_pkt(id:id);

      t1 = gettimeofday();
      if ( NASL_LEVEL < 4000 )
        rep = send_packet(pcap_active:TRUE, pcap_filter:icmp[1], pcap_timeout:1, icmp[0]);
      else
        rep = inject_packet(packet:link_layer() + icmp[0], filter:icmp[1], timeout:1);

      if(rep)
      {
        t2 = gettimeofday();
        rtt = NULL;
        #debug_print(get_host_ip(), ' answered to ICMP ping\n');
        set_kb_item(name: "/tmp/ping/ICMP", value: TRUE);
        # If the packet is not a valid answer to our ping, do not store the RTT
        hl = ord(rep[0]) & 0xF; hl *= 4;
        if (strlen(rep) >=  hl +8)
        {
          type = ord(rep[hl + 0]);
          code = ord(rep[hl + 1]);
          id2 = ord(rep[hl + 4]) * 256 + ord(rep[hl + 5]);
          if (type == 0 && code == 0 && id2 == icmpid)
            rtt = difftime2(t1: t1, t2: t2);
        }
        log_live(rtt: rtt, cause:"The remote host replied to an ICMP ping packet.");
      }
      j = j+1;
    }
    meth_tried += '- ICMP ping\n';
  }

  ###
  var dstports, srcports, requests, n, tid;

  if( 'yes' >< do_udp )
  {
    test++;
    n = 0;

    tid = raw_string(rand() % 256, rand() % 256);
    dstports[n] = 53;
    requests[n] = 
      tid +
      '\x00\x00' +		# Standard query (not recursive)
      '\x00\x01' +		# 1 question
      '\x00\x00' +		# 0 answer RR
      '\x00\x00' +		# 0 authority RR
      '\x00\x00' +		# 0 additional RR
      '\x03www' + '\x07example' + '\x03com' + '\x00' +
      '\x00\x01' +		# Type A
      '\x00\x01';		  # Classe IN
    n++;

    var xid = raw_string(rand() % 256, rand() % 256, rand() % 256, rand() % 256);
    dstports[n] = 111;
    requests[n] = 
      xid +			# XID
      '\x00\x00\x00\x00' +	# Call
      '\x00\x00\x00\x02' +	# RPC version = 2
      '\x00\x01\x86\xA0' +	# Programm = portmapper (10000)
      '\x00\x00\x00\x02' +	# Program version = 2
      '\x00\x00\x00\x03' +	# Procedure = GETPORT(3)
      '\0\0\0\0\0\0\0\0' +	# Null credential
      '\0\0\0\0\0\0\0\0' +	# Null verifier
      '\x00\x00\x27\x10' +	# programm 10000
      '\x00\x00\x00\x02' +	# version 2
      '\x00\x00\x00\x11' +	# UDP = 17
      '\x00\x00\x00\x00'; 	# port
    n++;

    # RIP v1 & v2 - some buggy agents answer only on requests coming from 
    # port 520, other agents ignore such requests. So I did a mix: v1 with
    # privileged source port, v2 without. 
    var v;
    for (v = 2; v >= 1; v --)
    {
      if (v == 1) srcports[n] = 520;
      dstports[n] = 520;
      requests[n] = raw_string(1, v, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 16);
      n++;
    }

    srcports[n] = 123;	# Or any client port
    dstports[n] = 123;
    requests[n] = '\xe3\x00\x04\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC6\x34\xFF\xE6\x4B\xAE\xAB\x79';
    n++;

    var sport, ip, udp, r, udpp, ipp, i, pkt, p2;
    for (j = 0; j < n; j ++)
    {
      if (srcports[j]) sport = srcports[j];
      else sport = rand() % 64512 + 1024;
      ip = forge_ip_packet(
        ip_v: 4, ip_hl: 5, ip_tos: 0, # Should we try TOS=16?
        ip_ttl: 0x40, ip_p: IPPROTO_UDP, 
        ip_src: compat::this_host(), ip_dst: get_host_ip()
      );
      udp = forge_udp_packet(ip: ip, uh_sport: sport, uh_dport: dstports[j],
      data: requests[j]);
      # No need to filter source & destination port: if we get a UDP packet, the
      # host is alive. But we do not listen for any packet, in case there is a
      # broken filter or IPS that sends fake RST, for example.
      filter = "src host " + get_host_ip() + " and dst host " + compat::this_host() + 
      " and (udp or (icmp and icmp[0]=3 and icmp[1]=3))";
      for (i = 0; i < 3; i ++)	# Try 3 times
      {
        t1 = gettimeofday();
        r = send_packet(udp, pcap_filter: filter, pcap_active: TRUE, pcap_timeout:1);
        if (r)
        {
          t2 = gettimeofday();
          var rtt = NULL;
          ipp = get_ip_element(ip: r, element: 'ip_p');
          #debug_print('Host answered to UDP request on port ', dstports[j], ' (protocol=', ipp, ')\n');
          if (ipp == 17)
          {
            udpp = get_udp_element(udp: r, element: 'uh_sport');
            p2 = get_udp_element(udp: r, element: 'uh_dport');
            set_kb_item(name:'/tmp/ping/UDP', value: udpp);
            if (udpp == dstports[j] && p2 == sport) rtt = difftime2(t1: t1, t2: t2);
            #if (udpp != dstports[j])
            #debug_print('Host sent an UDP packet from port ', udpp);
          }
          else if (ipp == 1)
          {
            hl = ord(r[0]) & 0xF; hl *= 4;
            pkt = substr(r, hl + 8);
            ipp = get_ip_element(ip: pkt, element: 'ip_p');
            if (ipp == 17)
            {
              rtt = difftime2(t1: t1, t2: t2);
            }
          }

          log_live(rtt: rtt, cause:"The remote host replied to a UDP request on port " + dstports[j] + ".");
        }
      }
    }

    ports = NULL;
    requests = NULL;
    meth_tried += '- UDP ping\n';
  }
}

####

if( test != 0 )
{
	if ( !isnull(meth_tried) )
		log_dead('The remote host (' + get_host_ip() + ') did not respond to the following ping methods :\n' + meth_tried);
	else
		log_dead();
}
