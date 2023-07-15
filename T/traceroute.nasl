#TRUSTED 76c765a41d6014ce80acc6f890f0a43d0cf51abff3bb0e4e34672105ec604856da56153913132c6b47e5b656114759e9f907ada5a7e78e806042337627babb00c1f543070a673a58a6afb98607bd101a910c33e1ab8fb7e6389112089fc665844129ed512e75b1a9e2f9ea981ecb04b00b79fd98e5a9cf3963339de7b7a09596dcc502e88234470c0f5aa2e374883cbbaecae1fab28687f3be003e7ad98bc55c81b895d5f20b3e64564e47d661517497025d8051dadb72905444b8174b0e2f735aefdaa63cb366a56c766a4bbc244f343e050e6ef509b1f26182816830ffc3a5631eb9279d766e836bb10c53836d7a49b1013f14224c93a88301af0c53c593aa94ea8f92f5ba0586866e2f709b8ac2bf28330cf4e2f1cb1bc5a5dbc596db2d48958db05488635773bf9e12391dc4239575b73797b4f4c9676369e3b99804176ede8a1f82730c0dfb125c6478211d952095415d2a02e9780d48f1dffc48634e5d05ee33a1dde7b1c1bedb34fa42e0e57fb29c3a117af35d729db47a84b2831441dfbeaf616ada4e47846284b8431224a909998e88a67901a797e73e90ebc6f60cba01dc42f8edfb7e2830c8b77de6ae144ad04615d4d803a31de683fce57201fa92e497c8c08e8bb40d35be03fb7a5007ccb3078e1de8b72541a323c97d74e28fda638c575b69d896f2eaefa485c99bf607ff09ebaf332e2232068364407ceedf
#TRUST-RSA-SHA256 591a3998b8dadc1fda959689c451748b1f506a60fd4510c9c557eed53550f5cd94d62fb37b33e2d7308481190937e7737058538fb2976144bc88a383140806b83bb1fc40e37669238a8d7aed3140f1b2a3a147cb8f86fbff7cbd07157030aaec6daaf7216767e5493e068f94ea7299fb55de2462a4c14bc0b3bbcbeef0aab77d02a99302064ee00fa7fdce12c5359c5fa6be321f7fa1bf3a75590b5ee05ee7e245aaf17c8e0ba5ffb559859f88dd130eceea2ac0252adb95e599b7baf94efaae4ff88a1521c1ad6f845368dc4ea03a89005e08c0b210f5924b9db818fb860bd79ac20642299d19eab0c20aaa2ff4811a6b18b8f54c2051d021901f173693ead1d43bfb547d362ff0d0cd1e04a301204dfb48b3dc858bf329a44cb03368f0de33803c198f39214e3d24e653538fdb983f8ca7ac4e0b0ab84aa76a3ea1acbc7d1721c1c0df21d62a6a3bee746f2b59d3c92ed5b50fe0cd3e48200eee2835b780a1f374e1a9649385cc7a69a2c0674b96d5b1c4a762fa74aa3f010ec7397821568609e1b794f3e1aea49e2aa96b809805e06b2fbfbcb496f7d9783d9ca56b73dd5d0fa6e9610162f16ec0c62e188dbe239f16a002a0e1cae0220e2ac8c2ceb6bb52437fbc0c5b2ddde41a78f4d3ef1b62d68d9d61107dffddf5542b3fc92b514ec1b2de774245dc432ce28ca5b9c27ec452f9390556be549bd0e4bec4f6b1b3caf6
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if ( isnull(nessus_version() ) ) exit(0);

if (description)
{
  script_id(10287);
  script_version("1.70");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

  script_name(english:"Traceroute Information");
  script_summary(english:"traceroute");

  script_set_attribute(attribute:"synopsis", value:"It was possible to obtain traceroute information.");
  script_set_attribute(attribute:"description", value:"Makes a traceroute to the remote host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2023 Tenable Network Security, Inc.");
  script_family(english:"General");
  exit(0);
}

#
# the traceroute itself
#

function make_pkt(ttl, proto)
{
  local_var ip, p, src;

  # proto = proto % 5;
  # display("make_pkt(", ttl, ", ", proto, ")\n");
  src = compat::this_host();

  # Prefer TCP
  if( proto == 0 || proto > 2)
  {
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_id:ip_id,
      ip_len:20, ip_off:0, ip_p:IPPROTO_TCP, ip_src:src, ip_ttl:ttl);

    p = forge_tcp_packet(ip:ip, th_sport:my_sport, th_dport:dport,
      th_flags:TH_SYN, th_seq:ttl, th_ack:0, th_x2:0, th_off:5,
      th_win:2048, th_urp:0);

    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Sending a forged TCP packet\n\n');
  }

  # then UDP
  if (proto == 1)
  {
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_id:ip_id,
      ip_len:28, ip_off:0, ip_p:IPPROTO_UDP, ip_src:src, ip_ttl:ttl);

    p = forge_udp_packet(ip:ip, uh_sport:my_sport, uh_dport:32768, uh_ulen:8);

    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Sending a forged UDP packet\n\n');
    return (p);
  }
  # then ICMP
  if (proto == 2)
  {
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_id:ip_id,
      ip_len:20, ip_off:0, ip_p:IPPROTO_ICMP, ip_src:src, ip_ttl:ttl);


    p = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:ttl, icmp_id:ttl);


    return (p);
  }

  return (p);
}

## MAIN ###

var gateway, dport, ip_id, my_sport,finished, ttl, src, dst,
error, str_ip, z, ip_fields, ip_high, ip_low, report, filter,
d, proto, gateway_n, count, i, err, p, rep, then, psrc, max, y;


if (TARGET_IS_IPV6) exit(0, "This check is not implemented for IPv6 hosts.");
if (islocalhost()) exit(1, "localhost can not be tested.");

dport = get_host_open_port();

if (!dport) dport = 80;

ip_id = rand() % 65535;

my_sport = rand() % 64000 + 1024;

finished = 0;
ttl = 1;
src = compat::this_host();
dst = get_host_ip();
error = 0;

dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' IP Address of Nessus Scanner - SRC: ' +  obj_rep(src) + '\n\n');
dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' IP Address of Destination Host - DST: ' +  obj_rep(dst) + '\n\n');

str_ip = dst;

z = strstr(str_ip, ".");

#
# pcap filter
#

ip_fields = split(dst, sep:'.', keep:0);
ip_high = (int(ip_fields[0]) << 8) | int(ip_fields[1]);
ip_low = (int(ip_fields[2]) << 8) | int(ip_fields[3]);

#
report = 'For your information, here is the traceroute from ' +
  src + ' to ' + dst + ' : \n' + compat::this_host() + '\n';

filter = "dst host " + src + " and ((icmp and ((icmp[0]=3) or " +
  "(icmp[0]=11)) and ((icmp[8] & 0xF0) = 0x40) and icmp[12:2]=" +
  ip_id + " and icmp[24:2]=" + ip_high + " and icmp[26:2]=" +
  ip_low + ")" + " or (src host " + get_host_ip() + " and tcp" +
  " and tcp[0:2]=" + dport + " and tcp[2:2]=" + my_sport +
  " and (tcp[13]=4 or tcp[13]=18)))";

d = get_host_ip();

proto = 0; # Prefer TCP
gateway_n = 0;

count = make_list();

if ( defined_func("platform") && platform() == "WINDOWS" && NASL_LEVEL >= 5000 ) mutex_lock(SCRIPT_NAME);

while(!finished)
{
  for (i=0; i < 3; i=i+1)
  {
    err=1;
    p = make_pkt(ttl: ttl, proto: proto);
    rep = send_packet(p, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);
    then = unixtime();

    if(rep)
    {
      psrc = get_ip_element(ip:rep, element:"ip_src");

      if (++ count[psrc] >= 3)
      {
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Encountered a loop: Plugin exiting \n\n');
        report += '\nTraceroute exit: Encountered a loop.\n'; # We are running in circles
        finished = 1;
        break;
      }

      gateway[gateway_n ++] = psrc;
      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Next Hop Identified : ' +  obj_rep(psrc) + '\n\n');
      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Traceroute list : ' +  obj_rep(gateway) + '\n\n');

      d = psrc - d;

      if (!d)
      {
        finished = 1;
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Traceroute has completed \n\n');
      }

      error = 0; err = 0;
      i = 666;
    }
    else
    {
      proto++;
      if (proto >= 3)
      {
        err = 1;
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'Unintended protocol detected ' + obj_rep(proto) + '\n\n');
        break;
      }
      else
      {
        err = 0;
        proto %= 3;
      }
    }
  }

  if (err)
  {
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' An error was detected along the way \n\n');
    report += '\nAn error was detected along the way.\n';
    if (!error)
    {
      gateway[gateway_n++] = '?';
      error = error + 1;

      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Error determining ' + gateway[gateway_n++] + '\n\n');

    }
  }

  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' ttl: ' +  obj_rep(ttl) + '\n\n');
  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg: crap(data:"=", length:70)+'\n');
  ttl = ttl + 1;

  #
  # If we get more than 3 errors one after another, we stop
  #
  if (error > 3)
  {
    finished = 1;
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' More than 3 errors have been reported - Completing Traceroute \n\n');
    report += '\nMore than 3 errors have been reported - Completing Traceroute.\n';
  }

  #
  # Should not get here
  #
  if (ttl > 50)
  {
    finished = 1;
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' ttl was greater than 50 - Completing Traceroute \n\n');
    report += '\nttl was greater than 50 - Completing Traceroute.\n';
  }
}

if (defined_func("platform") && platform() == "WINDOWS" && NASL_LEVEL >= 5000) mutex_unlock(SCRIPT_NAME);

max = 0;

for (i = 1; i < max_index(gateway); i ++)
{
  if (gateway[i] != gateway[i-1])
    max = i;
  else
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'Duplicate IP Detected : ' + i + ' ('+ gateway[i]+ ') in trace to '+ get_host_ip() + '\n\n');
}

for (i = 0; i <= max; i ++)
{
  if (empty_or_null(gateway[i])) continue;

  report = report + gateway[i] + '\n';
  report_xml_tag(tag:'traceroute-hop-' + i, value:gateway[i]);
  set_kb_item(name:'traceroute-hop/' + i, value:gateway[i]);
}

# hop count
report = report + '\nHop Count: ' + i + '\n';

# show if at least one route was obtained.
# MA 2002-08-15: I split the expression "ttl=ttl-(1+error)" because of
# what looked like a NASL bug
y = 1 + error;
ttl = ttl - y;
if (ttl > 0)
security_report_v4(port:0, proto:"udp", extra:report, severity:SECURITY_NOTE);
