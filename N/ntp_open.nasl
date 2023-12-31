#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10884);
 script_version("1.33");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_xref(name:"IAVT", value:"0001-T-0934");

 script_name(english:"Network Time Protocol (NTP) Server Detection");
 script_summary(english:"NTP allows query of variables.");

 script_set_attribute(attribute:"synopsis", value:
"An NTP server is listening on the remote host.");
 script_set_attribute(attribute:"description", value:
"An NTP server is listening on port 123. If not securely configured,
it may provide information about its version, current date, current
time, and possibly system information.");
 script_set_attribute(attribute:"see_also", value:"http://www.ntp.org");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_require_udp_ports(123);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("spad_log_func.inc");

app_name = "NTP Server";

port = 123;
if (!service_is_unknown(port:port, ipproto:"udp")) audit(AUDIT_NOT_LISTEN, app_name, port);

version = NULL;
system = NULL;
processor = NULL;
info = '';

function get_time(data)
{
  local_var time, time_raw;
  time = pregmatch(pattern:"clock=0x([0-9a-fA-F]+)", string:data);
  if(!time || empty_or_null(time[1]) || strlen(time[1]) != 8)
    return NULL;
  time_raw = hex2raw(s:time[1]);
  return uint(
      ord(time_raw[0]) << 24 |
      ord(time_raw[1]) << 16 |
      ord(time_raw[2]) << 8 |
      ord(time_raw[3])
    );



}
#
# Send an NTP init request to the server. If the NTP server is 
# using an ntp.conf where the following line is commented out
#
#       restrict -4 default kod notrap nomodify noquery
#
# the server will provide a response to an unauthenticated 
# connection requesting the NTP version information. 
# When building NTP from source the line mentioned 
# above is not enabled by default.
#
# NTP Version Request :
# 0000000  16 02 00 01 00 00 00 00  00 00 00 00    ........ ....
#
# NTP Version Response :
# 00000000  16 82 00 01 06 15 00 00  00 00 01 7d 76 65 72 73 ........ ...}vers
# 00000010  69 6f 6e 3d 22 6e 74 70  64 20 34 2e 32 2e 36 70 ion="ntp d 4.2.6p
# 00000020  35 40 31 2e 32 33 34 39  2d 6f 20 53 61 74 20 46 5@1.2349 -o Sat F
# 00000030  65 62 20 20 37 20 31 31  3a 30 35 3a 34 38 20 55 eb  7 11 :05:48 U
# 00000040  54 43 20 32 30 31 35 20  28 31 29 22 2c 0d 0a 70 TC 2015  (1)",..p
# truncated ...
#
# NTP Initialize Request :
# 00000000  1b 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 ........ ........
# 00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 ........ ........
# 00000020  00 00 00 00 00 00 00 00  54 9d 8f d6 b2 ba 12 b8 ........ T.......
#
# NTP Initialize Response :
# 00000000  1c 02 03 e9 00 00 13 49  00 00 0f cf ab 42 61 7e .......I .....Ba~
# 00000010  d8 a1 f0 31 1f 17 2a 8a  54 9d 8f d6 b2 ba 12 b8 ...1..*. T.......
# 00000020  d8 a1 f1 64 61 d6 60 66  d8 a1 f1 64 61 db fd 1e ...da.`f ...da...
# 
# The response in ascii should resemble the following
# AF_INET
# 123
# 172.26.25.221
# 172.26.25.221
#
# The ntp_init_req request will work across all NTP servers regardless
# of the settings in ntp.conf or authentication settings. This is 
# typically how clients initialize communication with an NTP server.
#

ntp_init_req = raw_string(
  0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x54, 0x9d, 0x8f, 0xd6, 0xb2, 0xba, 0x12, 0xb8
);

# ntp_vers_req packet
ntp_vers_req = raw_string(
  0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
);

# ntp_init_resp packet
ntp_init_resp = raw_string(
  0x54, 0x9d, 0x8f, 0xd6
);

# get the udp port state before connecting
if( !(get_udp_port_state(port)) )
  audit(AUDIT_PORT_CLOSED, port, "udp");

# open socket and prepare to send packets to ntp server
s = open_sock_udp(port);
if (!s) audit(AUDIT_SOCK_FAIL, port);

# send our init packet to the ntp server
send(socket:s, data:ntp_init_req);
data = recv(socket:s, length:1024);

if (empty_or_null(data)) audit(AUDIT_RESP_NOT, port);

# make sure we receive valid response from the ntp server
if (ntp_init_resp >!< data)
  audit(AUDIT_HOST_NOT, app_name);
else
  info += '\n  An NTP service has been discovered, listening on port '
       + port + '.\n';

# We now know ntp is open, but obtaining the version from the server
# requires a default configuration where the following line in
# ntp.conf does not exist.
#
# restrict -4 default kod notrap nomodify noquery

# send our version request to the ntp server
send(socket:s, data:ntp_vers_req);
data = recv(socket:s, length:1024);

#0 leap indicator,version,mode
#1 response,error,more,opcode
#2,3 sequence
#4,5 status
#6,7 association id
#8,9 offset
#10,11 count (data length)
#12+ data

stripped = "";
if (!empty_or_null(data))
{
  # data starts at byte 12
  send(socket:s, data:ntp_vers_req);
  data2 = recv(socket:s, length:1024);
  # get a time diff
  send(socket:s, data:ntp_vers_req);
  data3 = recv(socket:s, length:1024);
  send(socket:s, data:ntp_vers_req);
  data4 = recv(socket:s, length:1024);

  if (!empty_or_null(data2) && !empty_or_null(data3) && !empty_or_null(data4))
  {
    time1 = get_time(data:data);
    time2 = get_time(data:data2);
    time3 = get_time(data:data3);
    time4 = get_time(data:data4);
    diffs = make_list();
    count = 0;
    if(time1 && time2)
      diffs[count++] = time2 - time1;
    if(time2 && time3)
      diffs[count++] = time3 - time2;
    if(time3 && time4)
      diffs[count++] = time4 - time3;

    data1 = strip(substr(data, 12), pattern:'\x00\x0a\x0d');
    data2 = strip(substr(data2, 12), pattern:'\x00\x0a\x0d');
    data3 = strip(substr(data3, 12), pattern:'\x00\x0a\x0d');
    data4 = strip(substr(data4, 12), pattern:'\x00\x0a\x0d');

    sum = 0;
    limited = TRUE;
    debug_count = 1;
    var time;
    foreach time (diffs)
    {
      sum += time;
      limited = limited && time > 3;
      spad_log(message:"time diff "+debug_count+++" : "+ time);
    }

    spad_log(message:"data1 : "+serialize(data1));
    spad_log(message:"data2 : "+serialize(data2));
    spad_log(message:"data3 : "+serialize(data3));
    spad_log(message:"data4 : "+serialize(data4));
    spad_log(message:"time1 : "+time1);
    spad_log(message:"time2 : "+time2);
    spad_log(message:"time3 : "+time3);
    spad_log(message:"time4 : "+time4);
    time_avg = sum/count;
    # If the second or third ntp mode 6 requests are not rate-limited
    # track the support of mode6 responses, as it is not vulnerable
    # to amplification attacks. Cisco is rate-limiting at 4 seconds,
    # so set that as the threshold.
    if(limited || time_avg >= 3)
    {
      set_kb_item(name:'NTP/mode6_response_ratelimit', value:TRUE);
    }
    stripped = strip(substr(data, 12), pattern:'\x00\x0a\x0d');
    set_kb_item(name:"NTP/mode6_response", value:stripped);
  }
}
nodata = empty_or_null(stripped);
version = 'unknown';
system = 'unknown';
processor = 'unknown';
if (!nodata)
{
  # obtain version and patch level (e.g., v4.2.6p5)
  pattern = 'version="ntpd ([A-Za-z0-9./_-]*)';
  item = pregmatch(pattern:pattern, string:stripped);
  if(!isnull(item) && !isnull(item[1]))
    version = item[1];

  # obtain version from the response
  pattern = 'system="([A-Za-z0-9./_-]*)';
  item = pregmatch(pattern:pattern, string:stripped);
  if(!isnull(item) && !isnull(item[1]))
    system = item[1];

  # obtain version from the response
  pattern = 'processor="([A-Za-z0-9./_-]*)';
  item = pregmatch(pattern:pattern, string:stripped);
  if(!isnull(item) && !isnull(item[1]))
    processor = item[1];
}

register_service(port:port, proto:"ntp", ipproto:"udp");
set_kb_item(name:"NTP/Running", value:TRUE);
set_kb_item(name:"Services/ntp/version", value:version);
set_kb_item(name:"Host/OS/ntp", value:system);
set_kb_item(name:"Host/processor/ntp", value:processor);

if (nodata)
  info += '\n  No sensitive information has been disclosed.\n';
info += '\n  Version : ' + version + '\n';

security_report_v4(port:port, proto:"udp", extra:info, severity:SECURITY_NOTE);
