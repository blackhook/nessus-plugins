#TRUSTED 0ee991bb33abd4618abee94b552141a0fdd11c34683f7d4acf1a363b035250e800bb0d4473e2913f1b71d7269b92bcd912c8fd45f5b6de935b24636a30d37943993ab9f98440f740fa98ab351c2a6ec0e35bf211d13e880d1b4449a5a309779beebb7ebcdc34a8267e2711fce273452952e22b555acb35f54786f888edff3d0c843da6593145fc88e6b255c01e61a079bbb2af8f376174b86afe91847aafc6d7ca86da315b749d1c596eb3e480357ccad1bd371c7bf2ef1a9953f8b9cce9990caab2dad6037168cf1b88e1983bd56acad1d4e29995a1af6fa19f64d150ac0f7b0e86fa729e23024a189208ff588b50e2eea7c2439003ef941ba05ee760500ede1b9c3d9b9464b267533fb2d0f603229e6ed4da17cdddfcf416d23de75b84d2c67b8f5e52bb761ed7a530e0d68fd721f49aac39bffe50d0c2c84a908152f8f9095169094ade741f407808760c0059173437f03432156a2b62aa3160ec85ca09b3dea23546dc5ceaab7174dad4204fb32c02f2bd0f9481aee899dd81d8a5529e59ba6c2e9d7c7a7ebd64f6828a552e6812a080f5b8c77ba990f4824be26546e8e0bd49ebb0f7477b0d16f207cdf2235895a842839ebc8b36f8e1de9972c446f673580f8ea52b6d91ed365757a3eff57459f241bdaad9354bcb7be269c9ed71a8593a7a77486d9d2cac41fc2969fafa754f4f87d2fe03517de3c664f00106f31e1c
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25220);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/03/06");

  script_name(english: "TCP/IP Timestamps Supported");
  script_summary(english: "Look at RFC1323 TCP timestamps"); 
 script_set_attribute(attribute:"synopsis", value:
"The remote service implements TCP timestamps." );
  script_set_attribute(attribute:"description", value:
"The remote host implements TCP timestamps, as defined by RFC1323.  A
side effect of this feature is that the uptime of the remote host can
sometimes be computed." );
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc1323.txt" );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "General");
  script_copyright(english:"This script is Copyright (C) 2007-2019 Tenable Network Security, Inc.");

  exit(0);
}


include("raw.inc");

function ms_since_midnight()
{
  local_var     v, s, u;

  if (defined_func("gettimeofday"))
  {
    v = split(gettimeofday(), sep: '.', keep: 0);
    s = int(v[0]); u = int(v[1]);
    s %= 86400;
    u /= 1000;
    return u + 1000 * s;
  }

  if (defined_func("unixtime"))
  {
    s = unixtime();
    s %= 86400;
    return s * 1000;
  }

  return NULL;
}




if ( TARGET_IS_IPV6 ) exit(0, "This plugin is for IPv4 only.");
if ( islocalhost() ) exit(0, "The target is the localhost.");

dport = get_host_open_port(); 
if (! dport) exit(0, "No open port.");

daddr = get_host_ip();
saddr = compat::this_host();


function test(seq)
{
 local_var ip, tcp, options, filter, ms, r, sport, tsval;
 local_var i;
 local_var pkt;

 sport = rand() % (65536 - 1024) + 1024;
 ip = ip(ip_p:IPPROTO_TCP);
 tcp = tcp(th_sport:sport, th_dport:dport, th_flags:TH_SYN, th_win:512);
 tcp = tcp_insert_option(tcp:tcp, type:0x08, length:0x0A, data:mkdword(seq) + mkdword(0) + '\0x01\0x01');
 tcp = tcp_finish_insert_option(tcp:tcp);

 filter = strcat('tcp and src ', daddr, ' and dst ', saddr, ' and src port ', dport, ' and dst port ', sport);
 if ( ! defined_func("link_layer") )  RawSendViaOperatingSystem = 1;
 pkt = mkpacket(ip, tcp);
 for ( i = 0 ; i < 5 ; i ++ )
 {
  if ( ! defined_func("link_layer") )
  {
    r = send_packet(pkt,  pcap_active: TRUE, pcap_filter: filter, pcap_timeout:1);
    if ( !isnull(r) ) break;
  }
  else 
  {
   r = inject_packet(packet:link_layer() + pkt,filter:filter, timeout:1);
   if ( !isnull(r) ) 
	{
	 r = substr(r, strlen(link_layer()), strlen(r) - 1);
	 break; 
	}
   }
  }
 if ( r == NULL ) return NULL;
 ms = ms_since_midnight();

 pkt = packet_split(r);
 if ( isnull(pkt) ) return NULL;
 pkt = pkt[1];
 if ( isnull(pkt) || pkt["type"] != "tcp" ) return NULL;
 pkt = pkt["data"];
 if ( ! ( pkt["th_flags"] & TH_ACK) ) return NULL;
 if ( isnull(pkt["options"]) ) return NULL;
 tsval = tcp_extract_timestamp(pkt["options"]);
 if (isnull(tsval)) return NULL;
 return make_list(ms, tsval);
}

function tcp_extract_timestamp()
{
 local_var opt, lo, n, i, tsval, tsecr, len;
 
 opt = _FCT_ANON_ARGS[0];
 lo = strlen(opt);
 for (i = 0; i < lo; )
 {
  n = ord(opt[i]);
  if (n == 8)	# Timestamp
  {
   tsval = getdword(blob: substr(opt, i+2, i+5), pos:0);
   tsecr = getdword(blob: substr(opt, i+6, i+9), pos:0);
   #debug_print(level: 2, "TSVal=", tsval, " TSecr=", tsecr, "\n");
   return tsval;
  }
  else if (n == 1)	# NOP
   i ++;
  else
  {
   if ( i + 1 < strlen(opt) )
    len = ord(opt[i+1]);
   else 
    len = 0;
   if ( len == 0 ) break;
   i += len;
  }
 }
 return NULL;
}

function sec2ascii(txt, s)
{
 if (s < 60) return '';
 if (s < 3600)
  return strcat(txt, (s + 29) / 60, ' min');
 else if (s < 86400)
  return strcat(txt, (s + 1799) / 3600, ' hours');
 else
  return strcat(txt, (s + 23199) / 86400, ' days');
}

####

v1 = test(seq:1);

if (isnull(v1)) exit(0, "No valid TCP answer was received.");

# A linear regression would not be more precise and NASL is definitely not
# designed for computation! We would need floating point.
sleep(1);	# Bigger sleep values make the test more precise

v2 = test(seq: 2);
if (isnull(v2)) exit(1, "Invalid or no TCP answer."); # ???
else
{
 dms = v2[0] - v1[0];
 dseq = v2[1] - v1[1];

 #
 # Disable the uptime computation (unreliable)
 #
 if ( TRUE || dseq == 0 || v2[1] < 0)
 {
  security_note();
 }
 else
 {
  hz = dseq * 1000 / dms; hz0 = hz;
  # Round clock speed
  if (hz > 500) { hz = (hz + 25) / 50; hz *= 50; }
  else if (hz > 200) { hz = (hz + 5) / 10; hz *= 10; }
  else if (hz > 50) { hz = (hz + 2) / 5; hz *= 5; }
  #debug_print('dms = ', dms, ' - dseq = ', dseq, ' - clockspeed = ', hz0, ' rounded = ', hz, '\n');
  uptime = v2[1] / hz;
  #uptime = v2[1] * (dms / dseq) / 1000;
  txt = '';
  txt = sec2ascii(txt: ', i.e. about ', s: uptime);
  ov = (1 << 30) / hz; ov <<= 2;
  txt = strcat(txt, '.\n\n(Note that the clock is running at about ', 
	hz, ' Hz', 
	' and will\noverflow in about ', ov, 's', 
	sec2ascii(txt: ', that is ', s: ov));
  security_note(port: 0, 
	extra:strcat('The uptime was estimated to ', 
		uptime, 's', 
		txt, ')') );
 }
}
