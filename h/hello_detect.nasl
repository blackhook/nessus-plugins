#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# See RFC 831 & gated source (hello.h)
# http://www.zvon.org/tmRFC/RFC891/Output/chapter2.html
#


include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(11913);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"DCN HELLO detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote IP stack answers to an obsolete protocol.");
  script_set_attribute(attribute:"description", value:
"The remote host is running HELLO, an obsolete routing protocol.
If possible, this IP protocol should be disabled.");
  script_set_attribute(attribute:"solution", value:
"If this protocol is not needed, disable it or filter incoming traffic going
to IP protocol #63.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Settings/ThoroughTests");

  exit(0);
}

#
#                         1                   0 
#               5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
#          --- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# Fixed        |           Checksum            |
# Area         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |             Date              |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |                               |
#              +              Time             +
#              |                               |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |           Timestamp           |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |     Offset    |   Hosts (n)   |
#          --- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# Host         |          Delay Host 0         |
# Area         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |         Offset Host 0         |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#             ...                             ...
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |         Delay Host n-1        |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |         Offset Host n-1       |
#          --- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 
#                Figure 3. HELLO Message Format
# 

include('global_settings.inc');
include("network_func.inc");
##include("dump.inc");

if (islocalhost() || ! thorough_tests ) exit(0); 
if ( TARGET_IS_IPV6 ) exit(0);

s = compat::this_host();
v = eregmatch(pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9])+$", string: s);
if (isnull(v)) exit(0);

for (i = 1; i <=4; i++) a[i] = int(v[i]);

a1 = rand() % 256; a2 = rand() % 256;
s1 = rand() % 256; s2 = rand() % 256;

# Date is in RT-11 format, i.e. little endian, AFAIK. The date overflows
# in 2003 (!) so I suggest to tell them that we are at 2003-12-31 
# The source of gated gives more information than RFC 891. 2003-12-31 would
# give: 0x33FF; adding flags 0xC000 (Clock is unsynchronized) gives 0xF3FF

ms = ms_since_midnight();		# milliseconds since midnight
if (isnull(ms)) ms = rand();

r = raw_string(
	0, 0, 		# Checksum
	0xF3, 0xFF	# Date
	);
r += htons(n:ms);		# Time = ms since midnight
r  += raw_string(
	0, 0,		# Timestamp
	0,		# Offset (?)
	0 );		# Nb of hosts ??

ck = ip_checksum(data: r);
r2 = insstr(r, ck, 0, 1);

# HELLO is protocol 63
egp = forge_ip_packet(ip_v: 4, ip_hl: 5, ip_tos: 0, ip_p: 63, ip_ttl: 64,
			ip_off: 0, ip_src: compat::this_host(),	data: r2);

f = "ip proto 63 and src " + get_host_ip();
for ( i = 0 ; i < 3 ; i ++ )
{
 r = send_packet(egp, pcap_active: TRUE, pcap_filter: f, pcap_timeout:1);
 if ( r ) break;
}

if (isnull(r)) exit(0);

##hl = ord(r[0]) & 0xF; hl *= 4;
##hello = substr(r, hl);
##dump(dtitle: "hello", ddata: hello);

#ck = ip_checksum(data: hello);

security_note(port: 0, proto: "hello");
