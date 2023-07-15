#TRUSTED 4ff243b0e47542936f3c2aa918c12c2b7ba85a8f064a6c7c2c3a45d3948b71b591a9a75505c542e3f5225879ca804a4d3583d2be6a4489a8396ac6a90ccb35fb07e9ee125d4da42c69efe0bf34c8b97a54e3e1d95f3deaaf9df85b25e35e346d7faf1215a84da16b9fe40bded9c146054bcd59bef4f79cc947828da5f601a6bc3f56528e46ce7db0da9b4f359170f88e5e57b25a19e5f0a399ebf1ded975294f9ac1b3ef543b6856005c1254265b3e9b95d0231241cee441a33cdfeae9ecbdba0d607cb3c4db645a36122d7296338024f84b2141acef461ca83ad6496af4139b91db03684fd800629c01b38ba41166caa29c5c824b994027fe490c43a406cab535ee4d6a5c7609b4b23ba662a1bba6bf81984137c496e3974a5bc9921eddfd096fa3e2a7d5f0f91ae9dd84e576b269854f70d729acc768915254835399a0d8245acf28b71eb0287b003508b7cac13f29aa93755dfb332a640321018aa8436c0d8919e35ab2d8356f40b73140846321570e7634a6ad04164865319a33d8dd93ad43dc54675f13a31075ea0b459b52d98d9456bb53823a0d900fd2ec479e09afd9cedb6453dae6fba57f7b2b579d2be0fe1c4c7b9ed8130170bc7b60bc06d547d4a546845176a3c1090aa9570be36e35a3d27b18fbcc330211b6cc23f8869c9efab7d9d016bd0b0f046fc85a226f8638d14891c5e87a2a7dc33dca8d62d84c1b9a
#TRUST-RSA-SHA256 628cd92b2734be5faaebc31cf5fb56e6ddbdf5d235fc03d3e27b0dd722729ce82a4aa2d046241cbe973044566576ecb014c1f536dc506d4fa8d60afc9f04152113b81c4229138ad1bd889938707cb55f7333247a92e2fb106d503eda6fbfd03406094dfbefc93a69b959f9fb9a6da91ab2dca2c0e5e8e4c2d75491d5c1cb77c1728482b249ec2bcbcdea9d0d25aaaa1dea45670562feb28dfcde3f14ddf82e15723f63923404a1b8a28b18e81d825743e40617a8fdcb149ddaee15dcbd14fc44b0bcf2255565874f0c471e5b3c26d98ca614b70e1ff6918cdcffd509f3b68ec8023ec022887a2623f95edaef11af91414c82b8ec48a52ee697e705e29bcb05142c5dfdf76f7df8698a0d01911178e8ac7aaa76af2530e52bf1bfe1fe1b7ed9c45fa854d6e395b268b07f41133715129d804d90ee8373c6ae164de273440d51871116d4346fec9692f091d967656e48c17cd1746fdf3b476e10a493bb8120b6a25e933145f6f8ff4c5dc3ad60e2c574ebc1d8bd45011586dfe9fda37c03cc7494d2f5c490fd2afa88ade7f28f7e6703a9066e8a6f7ec2431bb81797f1945c922e48c72b7acd8895fe78f0912747cbb4213e2ef0e8ac7e1fb760c5c30c5255f4f3eea62b5640b5e6b5f8b3afc794b380c324391a09e1a469ef0dcd5dbac9137529b14789520c22894575581efd33bdbfc6f3672a5d56d592cdcc5cb24f50f9e938
#
# (C) Tenable Network Security, Inc.
#
#

# @PREFERENCES@

include("compat.inc");

if (description)
{
  script_id(22964);
  script_version("1.193");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_name(english:"Service Detection");
  script_summary(english:"Sends 'GET' to unknown services and looks at the answer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service could be identified.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote service by its banner or by
looking at the error message it sends when it receives an HTTP
request.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2004-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_timeout(0);
  script_add_preference(name:"Test SSL based services", type:"radio", value:"All ports");
  script_dependencies(
    "dcetest.nasl",
    "rpcinfo.nasl",
    "pjl_detect.nasl",
    "dont_scan_printers.nasl",
    "dont_scan_printers2.nasl",
    "zend_server_java_bridge_code_exec.nasl",
    "veritas_vxsvc_detect.nbin",
    "find_smtp.nasl",
    "emc_autostart_ftagent_detect.nbin",
    "hp_imc_dbman_detect.nbin",
    "dont_scan_ot.nasl"
  );

  exit(0);
}

include("global_settings.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ssl_funcs.inc");
include("datetime.inc");
include("debug.inc");
include('nessusd_product_info.inc');


if ( get_kb_item("global_settings/disable_service_discovery")  ) exit(0, "Service discovery has been disabled.");

# Clients sometime hit the default limit of 40MB allocations, especially with over 1000 ports open.
# We need to increase it. 200MB should be plenty for 1500 65k banners.
var mem = 200 * 1024 * 1024;
set_mem_limits(max_alloc_size:mem, max_program_size:mem);


#
# Global variables and constants
#
global_var g_sock, g_transport_state, g_sock_state, g_banners, g_timestamps, g_sock_conn_tries;
global_var g_port_pool, g_port_pool_idx, g_port_pool_max, state_to_transport, g_methods;
global_var g_ssl_ports, g_ssl_ports_H;

global_var g_ssl_ports_to_try, g_ssl_ports_to_try_idx;

global_var g_port_start_time, g_port_state_time;

global_var TLSv1_1_AVAILABLE = FALSE;
global_var TLSv1_2_AVAILABLE = FALSE;
global_var TLSv1_3_AVAILABLE = FALSE;

if (ENCAPS_TLSv1_1)
  TLSv1_1_AVAILABLE = TRUE;
if (ENCAPS_TLSv1_2)
  TLSv1_2_AVAILABLE = TRUE;
if (ENCAPS_TLSv1_3)
  TLSv1_3_AVAILABLE = TRUE;

global_var E_STATE_TLSv1       = 1;
global_var E_STATE_SSLv3       = 2;
global_var E_STATE_SSLv23      = 3;
global_var E_STATE_SSLv2       = 4;
global_var E_STATE_TLSv11      = 5;
global_var E_STATE_TLSv12      = 6;
global_var E_STATE_TLSv13      = 7;
global_var E_STATE_TLS_HELLO   = 8;
global_var E_STATE_SSL3_HELLO  = 9;
global_var E_STATE_SSL2_HELLO  = 10;
global_var E_STATE_IP          = 11;

global_var E_STATE_SSL_START = E_STATE_TLSv1;

global_var TIMEOUT = 5;
global_var SPONTANEOUS_TIMEOUT = 2;
global_var CONNECT_TIMEOUT = 4;
global_var CONNECT_RETRIES = 10;
global_var MAX_SIMULT_CONNECTIONS = 5;

global_var S_STATE_CONNECTING    = 1;
global_var S_STATE_READING       = 2;
global_var S_STATE_READING_W_GET = 3;
global_var S_STATE_DONE          = 4;

global_var S_STATE_DESCRIPTIONS = ['', 'S_STATE_CONNECTING', 'S_STATE_READING', 'S_STATE_READING_W_GET', 'S_STATE_DONE'];

global_var SSL_CONNECT_NONE = 0;
global_var SSL_CONNECT_ALL = 1;
global_var SSL_CONNECT_KNOWN = 2;

global_var SSL_PORT_TO_CONNECT = SSL_CONNECT_KNOWN;

state_to_transport = [];
if (nasl_level() >= 80900)
{
  state_to_transport[E_STATE_SSLv23] = ENCAPS_SSLv23 | ENCAPS_DISABLE_TLSv1_1 | ENCAPS_DISABLE_TLSv1_2 | ENCAPS_DISABLE_TLSv1_3;
}
else
{
  state_to_transport[E_STATE_SSLv23] = ENCAPS_SSLv23 | ENCAPS_DISABLE_TLSv1_1 | ENCAPS_DISABLE_TLSv1_2;
}

state_to_transport[E_STATE_SSLv2] = ENCAPS_SSLv2;
state_to_transport[E_STATE_TLSv1] = ENCAPS_TLSv1;
state_to_transport[E_STATE_SSLv3] = ENCAPS_SSLv3;
state_to_transport[E_STATE_TLSv11] = ENCAPS_TLSv1_1;
state_to_transport[E_STATE_TLSv12] = ENCAPS_TLSv1_2;
state_to_transport[E_STATE_TLSv13] = ENCAPS_TLSv1_3;
state_to_transport[E_STATE_TLS_HELLO] = ENCAPS_IP;
state_to_transport[E_STATE_SSL3_HELLO] = ENCAPS_IP;
state_to_transport[E_STATE_SSL2_HELLO] = ENCAPS_IP;
state_to_transport[E_STATE_IP]    = ENCAPS_IP;

g_ssl_ports = [
  261,    # Nsiiops
  443,    # HTTPS
  446,    # Openfiler's management interface
  448,    # ddm-ssl
  465,    # SMTPS
  563,    # NNTPS
  585,    # imap4-ssl
  614,    # SSLshell
  636,    # LDAPS
  684,    # Corba IIOP SSL
  695,    # IEEE-MMS-SSL
  853,    # DNS over TLS
  902,    # VMWare Auth Daemon
  989,    # FTPS data
  990,    # FTPS control
  992,    # telnets
  993,    # IMAPS
  994,    # IRCS
  995,    # POP3S
  1032,   # HP Server Automation (twisted web interface)
  1241,   # Nessus
  1243,   # PVS Proxy
  1311,   # Dell OpenManage
  1950,   # Tivoli Security Configuration Manager agent
  2010,   # IBM HTTP Server administration SSL port
  2050,   # Domino
  2161,   # APC UPS Power Monitoring Agent
  2224,   # Pacemaker PCSD Service
  2381,   # Compaq Web Management
  2456,   # SGMI (Remote firewall management)
  2478,   # SecureSight Authentication Server
  2479,   # SecureSight Event Logging Server
  2482,   # Oracle GIOP SSL
  2484,   # Oracle TTS SSL
  2679,   # Sync Server SSL
  2738,   # HP DDMI
  3037,   # Novell File Reporter Agent
  3077,   # Orbix 2000 Locator SSL
  3078,   # Oribx 2000 Locator SSL
  3220,   # Juniper Junos XML protocol server (over SSL)
  3269,   # Microsoft Global Catalog w/ LDAP/SSL
  3389,   # Microsoft Remote Desktop
  3424,   # Xware xTrm Communication Protocol over SSL (xtrms)
  3471,   # jt400 SSL
  3661,   # IBM Tivoli Directory Service using SSL
  3780,   # Nexpose
  3790,   # Metasploit HTTPS Server
  3994,   # IIS deployment manager
  4031,   # UUCP over SSL
  4343,   # Trend Micro Worry-Free Business Security Web Console
  4445,   # PCI
  5007,   # WSM Server SSL
  5061,   # SIP over TLS
  5443,   # IBM WebSphere Commerce Payments secure server
  5480,   # VMware vRealize Automation and SolarWinds Virtualization Manager
  5556,   # Oracle WebLogic Node Manager
  5666,   # Nagios Remote Plugin Executor (NRPE)
  5671,   # Advanced Message Queueing Protocol -- SSL
  5783,   # 3PAR Management Service
  5988,   # SBLIM Small Footprint CIM Broker
  5989,   # SBLIM Small Footprint CIM Broker
  6697,   # IRC/SSL
  6783,   # Splashtop Streamer SSL port
  6784,   # Splashtop Streamer SSL port
  6785,   # Splashtop Streamer SSL port
  6789,   # Sun Java Web Console
  7002,   # WebLogic
  7004,   # RSA Secure Logon
  7071,   # Zimbra Collaboration Server
  7135,   # IBM Tivoli Access Manager runtime env -- SSL
# IANA lists a different service assigned to TCP 7101
# 7101,   # Oracle Enterprise Manager Admin Server (HTTPS)
  7183,   # Cloudera Manager
  7301,   # Oracle Enterprise Manager Cloud Control Managed Server (HTTPS)
  7403,   # Oracle Enterprise Manager Grid Control Node Manager (HTTPS)
  7700,   # Bosch Security System Ethernet Connection Module
  7799,   # Oracle Enterprise Manager Console
  8000,   # Tenable Appliance / IBM WebSphere Commerce Accelerator
  8002,   # IBM WebSphere Commerce Server Admin Console
  8004,   # IBM WebSphere Commerce Server Organization Administration Console
  8006,   # IBM WebSphere Commerce preview
  8009,   # Sony Bravia TV
  8012,   # Citrix XenServer Workload Balancer
  8082,   # BlueCoat ProxySG Console
  8089,   # Splunk management port
  8139,   # Puppet agent
  8140,   # Puppet master
  8333,   # VMware
  8443,   # Tomcat
  8444,   # McAfee ePolicy Orchestrator
  8445,   # Symantec SEPM
  8834,   # Nessus 4.2
  8835,   # PVS 4.0
  8880,   # IBM WebSphere Application Server SOAP connector
  9000,   # Sony Bravia
  9002,   # Oracle WebLogic Administration Port
  9043,   # IBM WebSphere Application Server administrative console secure port
  9390,   # OpenVAS Manager
  9391,   # OpenVAS Scanner
  9392,   # Greenbone Security Assistant
  9393,   # OpenVAS Administrator
  9443,   # WebSphere internal secure server
  9090,   # HP iNode Management Center
  10000,  # Webmin+SSL
  10443,  # McAfee Email Gateway
  11090,  # IBM Spectrum Protect Operations Center
  13841,  # HP VSA hydra 10.0
  18443,  # MySQL Enterprise Monitoring
  18630,  # StreamSets DataCollector
  18636,  # StreamSets DataCollector
  19201,  # SilPerformer agent
  40007,  # AlienVault OSSIM SOAP
  40011,  # AlienVault OSSIM REST
  42966,  # HP Remote Graphics
  50000,  # HP Insight Software
  54345,  # HP Load Runner
  54984,  # WebYaST Web Client
  63002,  # HP Smart Update Manager
  65443   # McAfee LinuxShield nailsd
];

#
# Initialize the variables
#

function globals_reset()
{
  g_sock_state = {};
  g_sock = {};
  g_transport_state = {};
  g_banners = {};
  g_timestamps = {};
  g_methods = {};
  g_sock_conn_tries = {};
  g_port_start_time = {};
  g_port_state_time = {};
  g_port_pool = [];
  g_port_pool_max = 0;
  g_port_pool_idx = 0;
}

function globals_init()
{
  globals_reset();

  g_ssl_ports_to_try_idx = 0;
  g_ssl_ports_to_try = {};
}

#-------------------#
# Helper functions  #
#-------------------#

##
# Determine total elapsed time from provided start
#
# @anonparam start staring time (gettimeofday() epoch)
#
# @return difference between start and current gettimeofday() if start,
#         else NULL
#
##
function timediff()
{
  var start = _FCT_ANON_ARGS[0];
  if (empty_or_null(start)) return NULL;
  return datetime::timeofday_diff(begin:start, end:gettimeofday());
}

##
# Transition to next state for the provided port.
#
# @param port Port to transition states on
#
# @return NULL
##
function transition_state(port)
{
  # If >= 8.9 skip SSLv2 state
  if (nasl_level() >= 80900 && ((g_transport_state[port] + 1) == E_STATE_SSLv2))
  {
    g_transport_state[port] += 2;
  }
  else
  {
    g_transport_state[port]++;
  }
}

#----------------------#
# Service recognition  #
#----------------------#

function SSL_hello(port)
{
  var ver, cipherspec, cspeclen, chello, hello_done, data, rec, cipher, n;
  var soc, state, exts, exts_len, rec_ver, port_start_time, recv_start_time;

  port_start_time = gettimeofday();
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
    'Port ' + port + ' test starting...');

  soc = g_sock[port];
  state = g_transport_state[port];

  cipherspec = NULL;
  ver = NULL;

  # Detect SSLv3+, TLS servers should support backward compatibility
  if(state != E_STATE_SSL2_HELLO)
  {
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Port ' + port + ' - detected SSLv3 or later. Attempting negotiation...');
    if (state == E_STATE_TLSv13)
    {
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
        'Trying TLS 1.3...');
      chello = tls13_client_hello();
      send(socket:soc, data:chello);

      data = recv_ssl(socket:soc, hard_timeout:TRUE);

      # Server hello
      rec = ssl_find(
        blob:data,
        'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
        'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
      );
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
        'Port ' + port + ' test completed in ' + timediff(port_start_time) + ' seconds');
      # check our server version is 3,3 and our extension supported version is TLS 1.3
      if ( !isnull(rec) && rec['handshake_version'] == 0x0303 && rec['extension_supported_versions'][0] == 0x0304)
        return TLS_13;
      else
        return -3;
    }
    else
    {
      # not TLS 1.3
      cipherspec = get_valid_cipherspec_for_encaps(encaps:COMPAT_ENCAPS_TLSv12, ciphers:ciphers);
      cipherspec += raw_string(0x00, 0xff);
      cspeclen = mkword(strlen(cipherspec));

      rec_ver = raw_string(3,1);
      exts = tls_ext_ec() + tls_ext_ec_pt_fmt();
      exts_len  = mkword(strlen(exts));

      if(state == E_STATE_SSL3_HELLO)
      {
        rec_ver = raw_string(3,0);
        exts = exts_len = NULL;
      }
      chello = client_hello(
        v2hello      :FALSE,
        version      : rec_ver,
        cipherspec   : cipherspec,
        cspeclen     : cspeclen,
        extensions   : exts,
        extensionslen: exts_len,
        maxver       : raw_string(3,3)
      );
      send(socket:soc, data:chello);
      hello_done = FALSE;
      n = 0;
      while ( ! hello_done )
      {
        if ( n++ > 64 ) return -1;
        recv_start_time = gettimeofday();
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
          'Port ' + port + ' recv_ssl() iteration: ' + n + ' starting...');
        data = recv_ssl(socket:soc, hard_timeout:TRUE);
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
          'Port ' + port + ' recv_ssl() iteration: ' + n + ' completed in ' + timediff(recv_start_time) + ' seconds');

        if ( isnull(data) ) return -2;

        # Server Hello
        rec = ssl_find(
          blob:data,
          'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
          'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
        );
        if ( !isnull(rec) )
        {
          if( !isnull(rec['handshake_version']))
            ver = rec['handshake_version'];
          else
            return -3;
        }
        # Server Hello Done.
        rec = ssl_find(
          blob:data,
          'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
          'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
        );

        if ( !isnull(rec) ) hello_done = TRUE;
      }
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
        'Port ' + port + ' test completed in ' + timediff(port_start_time) + ' seconds');
      return ver;
    }
  }
  # Detect SSLv2 server
  else
  {
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Port ' + port + ' - detected SSLv2. Attempting negotiation...');

    foreach cipher (sort(keys(ciphers)))
    {
      if('SSL2_' >< cipher)
      {
         cipherspec +=  ciphers[cipher];
      }
    }
    cspeclen = mkword(strlen(cipherspec));

    chello = client_hello(
      version    : raw_string(0,2),
      cipherspec : cipherspec,
      cspeclen   : cspeclen,
      v2hello    : TRUE
    );

    send(socket:soc, data:chello);

    recv_start_time = gettimeofday();
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Port ' + port + ' recv_ssl() for SSLv2 starting...');
    data = recv_ssl(socket:soc, hard_timeout:TRUE);
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Port ' + port + ' recv_ssl() for SSLv2 completed in ' + timediff(recv_start_time) + ' seconds');

    if ( isnull(data) ) return -2;

    rec = ssl_find(
      blob:data,
     "content_type", SSL2_CONTENT_TYPE_SERVER_HELLO
    );
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
      'Port ' + port + ' test completed in ' + timediff(port_start_time) + ' seconds');
    if(! isnull(rec))
    {
      if(! isnull(rec['version']))
        return rec['version'];
      else
        return -3;
    }
    else
      return -4;
  }
}

function is_ssl_banner()
{
  var banner;

  banner = _FCT_ANON_ARGS[0];

  if ( strlen(banner) < 5 ) return FALSE;

  if (  (substr(banner, 0, 2 ) == raw_string(0x15, 0x03, 0x01)) ||
        (substr(banner, 0, 4 ) == raw_string(0x15, 0x03, 0x00, 0x00, 0x02)) ||
        (substr(banner, 0, 4 ) == raw_string(0x80, 0x03, 0x00, 0x00, 0x01)) ||
       "error:1407609C:SSL routines:" >< banner )
    return TRUE;
  else
    return FALSE;
}

function three_digits(port, banner)
{
  if ( banner && banner =~ "^[0-9][0-9][0-9]($|-| )" )
  {
    set_kb_item(name:"Services/three_digits", value:port);
    return 1;
  }
}

function report_finding(port, proto, name, transport)
{
  var data;
  if ( isnull(name) ) name = 'A ' + proto + ' server';
  register_service(port:port, proto:proto);

  # Don't save www banners from an HTTP 1.0 request as they may
  # cause problems for scans of name-based virtual hosts.
  if ( '\0' >!< g_banners[port] && proto != "www" && !empty_or_null(g_banners[port]))
    replace_kb_item(name:proto + "/banner/" + port, value:g_banners[port]);

  # weblogic speaks 5 different protocols off the same port. flag this
  # http service as potentially wls early so that the downstream protcols
  # can examine this list
  if (proto == "www")
  {
    set_kb_item(name:'www/possible_wls', value:port);
  }

  data = name + ' is running on this port';
  if ( transport == ENCAPS_SSLv2 ) data +=' through SSLv2.';
  else if ( transport == ENCAPS_SSLv3 ) data +=' through SSLv3.';
  else if ( transport == ENCAPS_SSLv23 ) data +=' through SSLv23.';
  else if ( transport == ENCAPS_TLSv1 ) data +=' through TLSv1.';
  else if ( transport == COMPAT_ENCAPS_TLSv11 ) data +=' through TLSv1.1.';
  else if ( transport == COMPAT_ENCAPS_TLSv12 ) data +=' through TLSv1.2.';
  else if ( transport == COMPAT_ENCAPS_TLSv13 ) data +=' through TLSv1.3.';
  if (data[strlen(data)-1] != '.') data += '.';

  security_note(port:port, extra:data);
  return NULL;
}

function may_be_time()
{
  var now, rt70, diff_1970_1900, max_shift;

  diff_1970_1900 = 2208988800;
  max_shift = 3*365*86400;

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);
  rt70 = getdword(blob:_FCT_ANON_ARGS[0], pos:0) - diff_1970_1900;

  now = unixtime() - rt70;
  if ( now < 0 ) now = 0 - now;
  if ( now < max_shift ) return TRUE;
  else return FALSE;
}

function register_unknown(port, banner)
{
  if (strlen(banner) && banner =~ "^[0-9][0-9][0-9]($|-| )" ) return 0; # 3 digits

  set_kb_item(name:"Services/unknown", value:port);
  if ( strlen(banner) ) replace_kb_item(name:"unknown/banner/" + port, value:banner);
  return 0;
}

function register_silent()
{
  var port;
  port = _FCT_ANON_ARGS[0];
  set_kb_item(name:"Services/Silent/" + port , value:TRUE);
  set_kb_item(name:"Services/Silent", value:port);
  return 0;
}

#
# Signature based recognition
#
function recognize_banner(banner, port, transport)
{
  var low, is_http, info, ver;

  is_http = 0;

  if ( strlen(banner) == 0 )
    return register_unknown(port:port, banner:banner);

  low = tolower(banner);

  if ( is_ssl_banner(banner) &&
       should_try_ssl(port) == FALSE &&
       transport == ENCAPS_IP )
  {
    g_ssl_ports_to_try[g_ssl_ports_to_try_idx++] = port;
    return NULL;
  }

  if (low =~ "^<html>" && "<TITLE>Directory /</TITLE>" >< banner)
  {
    report_finding(port:port, proto:"wild_shell", name:"A bind shell", transport:transport);
  }
  else if ( low =~ "^http/[0-9]\." || "<title>Not supported</title>" >< low || low =~ "^<html>" )
  {
    # HTTP server
    # MA 2008-07-16: we used to skip port 5000 because of vtun
    if ( ! ( low =~ "^http/1\.0 403 forbidden" && "server: adsubtract" >< low ) &&
         ! ( "server: flashcom/" >< low )  &&
         ! ( "server: heimdal/"  >< low ) &&
         ! ( low =~ "^cimerror: ") )
    {
      is_http = 1;
      if ( "mongodb over http on the native driver port" >< low )
      {
        report_finding(port:port, proto:"mongodb-http", name:"MongoDB HTTP", transport:transport);
      }
      else if (
        low =~ "^http/1\.[01] (101 switching protocols|426 upgrade required)" &&
        'upgrade: websocket' >< low)
      {
        report_finding(port:port, proto:"websocket", name:"A WebSocket", transport:transport);
      }
      else
      {
        report_finding(port:port, proto:"www", name:"A web server", transport:transport);
      }
    }
  }

  # Telnet-related services
  if (strlen(banner) > 2 &&
      ord(banner[0]) == 255 && ord(banner[1]) >= 251 && ord(banner[1]) <= 254)
  {
    # Regular Telnet is always the last one (inside else)
    # we need a new socket for retrieving the telnet banner
    var telnet_soc = open_sock_tcp(port), telnet_banner;
    if (telnet_soc)
    {
      telnet_banner = telnet_negotiate(socket:telnet_soc);
      close(telnet_soc);
    }
    g_banners[port] = telnet_banner;
    if ("Welcome To jdkchat" >< telnet_banner && "Commands available:" >< telnet_banner)
    {
      return report_finding(port:port, proto:"jdkchat", name:"A Telnet Chat Server from J.D. Koftinoff Software", transport:transport);
    }
    else if ( "Eggdrop" >< telnet_banner || "Eggheads" >< telnet_banner )
    {
      return report_finding(port:port, proto:"eggdrop", name:"An eggdrop IRC bot control server", transport:transport);
    }
    else if ("communicating without encryption but connections from clients that do not support encryption are not allowed" >< telnet_banner && "CLEARTEXT option" >< telnet_banner)
    {
      return report_finding(port:port, proto:"SAS-CONNECT", name:"A SAS/CONNECT Server", transport:transport);
    }
    else if (hexstr(banner) == 'fffb010a' && (port == 13846 || port == 13847 || port == 13850 || port == 13946))
    {
      return report_finding(port:port, proto:"lefthand-os-support", name:"An HP StoreVirtual (LeftHand) Storage server", transport:transport);
    }
    else
    {
      # regular telnet
      return report_finding(port:port, proto:"telnet", transport:transport);
    }
  }
  else if ( "ccproxy telnet service ready" >< low)
    return report_finding(port:port, proto:"ccproxy-telnet", name:"A CCProxy Telnet proxy", transport:transport);

  else if ( strlen(banner) >= 4 &&
            substr(banner, 0, 3) == '\00\01\01\00')
    return report_finding(port:port, proto:"gnome14",name:"Gnome 1.4", transport:transport);

  else if ( "http/1.0 403 forbidden" >< low && "server: adsubtract" >< low )
  {
    return report_finding(port:port, proto:"AdSubtract",name:"A locked AdSubtract server", transport:transport);
  }

  else if ( "server: flashcom/" >< low )
  {
    return report_finding(port:port, proto:"rtmp",name:"Flash Media Server", transport:transport);
  }

  else if ( low =~ "^\$lock" )
    return report_finding(port:port, proto:"DirectConnectHub", name:"A Direct Connect Hub", transport:transport);

  else if ( strlen(low) > 34 && "iss ecnra built-in provider" >< substr(low, 34, strlen(low) - 1 ) )
    return report_finding(port:port, proto:"issrealsecure", name:"ISS RealSecure", transport:transport);

  else if ( strlen(banner) == 4 && banner == 'Q\00\00\00\00' )
    return report_finding(port:port, proto:"cpfw1", name:"Check Point FW1 SecuRemote or FW1 FWModule", transport:transport);

  else if ( low =~ "^ssl-tunnel/[0-9.]+ prot/[0-9.]+" )
    return report_finding(port:port, proto:"ssltunnel", name:"SSLTunnel (a VPN solution)", transport:transport);

  else if ( "adsgone blocked html ad" >< low )
    return report_finding(port:port, proto:"adsgone", name:"An AdsGone server", transport:transport);

  else if ( low =~ "icy 200 ok" )
    return report_finding(port:port, proto:"shoutcast",  transport:transport);

  else if (
    low =~ "^200.*running eudora internet mail server" ||
    "+ok applepasswordserver" >< low   ||
    low =~ "^220.*poppassd" ||
    low =~ "^200.*poppassd" ||
    low =~ "^poppassd hello" )
  {
    return report_finding(port:port, proto:"pop3pw", transport:transport);
  }

  else if ( banner =~ "^220" && " SNPP" >< banner )
  {
    return report_finding(port:port, proto:"snpp", name:"An SNPP server", transport:transport);
  }

  else if ( getdword(blob:banner, pos:0) == (strlen(banner) - 4) &&
            "krbtgt" >< banner )
  {
    return report_finding(port:port, proto:"krbtgt", name:"A Kerberos ticket server", transport:transport);
  }

  else if ( "ccproxy" >< low && "smtp service ready" >< low)
    return report_finding(port:port, proto:"ccproxy-smtp", name:"A CCProxy SMTP proxy", transport:transport);

  else if ( (
    "smtp" >< low ||
    "simple mail transfer" >< low ||
    "mail server" >< low ||
    "messaging" >< low ||
    "connection rate limit exceeded" >< low ||
    "weasel" >< low) && low =~ "^(220|421)" )
     return report_finding(port:port, proto:"smtp", name:"An SMTP server", transport:transport);

  # FTV-40905-469: False detection of an FTP server
  # "220 ***************" >< banner
  else if (low =~ "^220 esafe(@|alert)" ||
           low =~ "^220.*groupwise internet agent" )
    return report_finding(port:port, proto:"smtp", name:"An SMTP server", transport:transport);

  else if ( ord(low[0]) != 0 && "host '" >< low && "mysql" >< low )
    return report_finding(port:port, proto:"mysql", name:"A MySQL server", transport:transport);
  else if ( ord(low[0]) != 0 && "host '" >< low && "mariadb" >< low )
    return report_finding(port:port, proto:"mysql", name:"A MariaDB server", transport:transport);
  else if ( ord(low[0]) != 0 && "can't create a new thread (errno" >< low && "if you are not out of available memory, you can consult" >< low )
    return report_finding(port:port, proto:"mysql-broken", name:"A MySQL server which is out of resources", transport:transport);

  else if ( low =~ "^efatal" ||
            low =~ "^einvalid packet length" )
    return report_finding(port:port, proto:"postgresql", name:"A PostgreSQL server", transport:transport);

  else if ( "cvsup server ready" >< low )
    return report_finding(port:port, proto:"cvsup", name:"A CVSup server", transport:transport);


  else if ( low =~ "cvs \[p?server aborted\]:" )
    return report_finding(port:port, proto:"cvspserver", name:"A CVS pserver", transport:transport);


  else if ( low =~ "^cvslock" )
    return report_finding(port:port, proto:"cvslock", name:"A CVSLock server", transport:transport);

  else if ( low =~ "@rsyncd" )
    return report_finding(port:port, proto:"rsyncd", name:"An rsync server", transport:transport);

  else if ( strlen(banner) == 4 && may_be_time(banner) )
    return report_finding(port:port, proto:"time", name:"A time server", transport:transport);

  else if ( ("rmserver" >< low || "realserver" >< low) && "server: apache" >!< low )
    return report_finding(port:port, proto:"realserver", name:"A RealMedia server", transport:transport);

  else if ( "ccproxy ftp service" >< low )
    return report_finding(port:port, proto:"ccproxy-ftp", name:"A CCProxy FTP proxy", transport:transport);

  else if ( ("ftp" >< low ||
             "winsock" >< low ||
             "axis network camera" >< low ||
             "netpresenz" >< low ||
             "serv-u" >< low ||
             "service ready for new user" >< low ) && low =~ "^2[23]0" )
    return report_finding(port:port, proto:"ftp", name:"An FTP server", transport:transport);
  else if ( low =~ "^220-"  && port != 25 && port  != 63  && port != 2628  )
    return report_finding(port:port, proto:"ftp", name:"An FTP server", transport:transport);

  else if ( low =~ "^220" && "whois+" >< low )
    return report_finding(port:port, proto:"whois++", name:"A whois++ server", transport:transport);
  else if ( "520 command could not be executed" >< low )
    return report_finding(port:port, proto:"mon", name:"A mon server", transport:transport);

  else if ( pgrep(pattern:"^SSH-[0-9.]+-", string:banner) )
    return report_finding(port:port, proto:"ssh", name:"An SSH server", transport:transport);

  else if ( pgrep(pattern:"^relaylock: ", string:banner) )
    return report_finding(port:port, proto:"plesk-relay-lock", name:"An broken relay-lock server", transport:transport);

  else if ( "ok welcome to the nails statistics service" >< low)
    return report_finding(port:port, proto:"nailsd", name:"NAILS Statistics Service from McAfee LinuxShield", transport:transport);

  else if ( "ccproxy" >< low && "pop3 service ready" >< low)
    return report_finding(port:port, proto:"ccproxy-pop3", name:"A CCProxy POP3 proxy", transport:transport);

  else if ( low =~ "^\+ok" ||
    ( low[0] == '+' && "pop" >< low ) )
  {
    if ( port == 109 )
      return report_finding(port:port, proto:"pop2", name:"A POP2 server", transport:transport);
    else
      return report_finding(port:port, proto:"pop3", name:"A POP3 server", transport:transport);
  }
  else if ( low =~ "^\+ok *hello there" )
    return report_finding(port:port, proto:"pop3", name:"A POP3 server", transport:transport);
  else if ( low =~ "^\-err this server is currently" )
    return report_finding(port:port, proto:"broken-pop3", name:"A POP3 server under maintenance", transport:transport);

  else if ( ("imap4" >< low && low =~ "^\* ?ok") ||
            low =~ "^\*ok iplanet messaging multiplexor" ||
            low =~ "^\*ok communigate pro imap server" ||
            low =~ "^\* ok courier-imap" ||
            low =~ "^\* ok dbmail imap" ||
            (low =~ "^\* ok server ready" && "unauthorized access prohibited." >< low) ||
            low =~ "^\* ok imaprev1" )
    return report_finding(port:port, proto:"imap", name:"An IMAP server", transport:transport);

  else if ( low =~ "^giop" )
    return report_finding(port:port, proto:"giop", name:"A GIOP-enabled service", transport:transport);

  else if ( "microsoft routing server" >< low )
    return report_finding(port:port, proto:"exchg-routing", name:"A Microsoft Exchange routing server", transport:transport);

  else if ( "gap service ready" >< low )
    return report_finding(port:port, proto:"iPlanetENS", name:"iPlanet ENS (Event Notification Server)", transport:transport);

  else if ("-service not available" >< low )
    return report_finding(port:port, proto:"tcpmux", transport:transport);
  else if ( strlen(banner) > 2 &&
            substr(banner,0,4) == '\x7f\x7fICA' )
    return report_finding(port:port, proto:"citrix", name:"A Citrix server", transport:transport);
  else if (  "496365500100010003000e000000" >< hexstr(banner) )
    return report_finding(port:port, proto:"hp-remote-graphics", name:"An HP Remote Graphics server", transport:transport);
  else if ( banner =~ "^[0-9][0-9][0-9][ -]" &&
            (" INN " >< banner ||
             " Leafnode " >< banner ||
             "  nntp daemon" >< low ||
             " nnrp service ready" >< low ||
             " nntp server ready" >< low ||
             "posting ok"  >< low ||
             "posting allowed" >< low ||
             "502 no permission" >< low ||
             low =~ "^502.*diablo"  ) )
    return report_finding(port:port, proto:"nntp", name:"An NNTP server", transport:transport);

  else if (  "networking/linuxconf" >< low ||
      "networking/misc/linuxconf" >< low ||
      "server: linuxconf" >< low )
    return report_finding(port:port, proto:"linuxconf", name:"LinuxConf", transport:transport);

  else if ( banner =~ "^gnudoit:" )
    return report_finding(port:port, proto:"gnuserv", name:"A GNUserv server", transport:transport);

  else if ( strlen(banner) > 5 &&
     ( banner[0] == '0' && 'error.host\t1' >< low ) ||
     ( banner[0] == '3' && 'That item is not current available' >< banner ) ||
     ( banner[0] == '3' && "--6 Bad Request" >< banner ) )
    return report_finding(port:port, proto:"gopher", name:"A Gopher server", transport:transport);

  else if ('www-authenticate: basic realm="swat"' >< low )
    return report_finding(port:port, proto:"swat", name:"A SWAT server", transport:transport);

  else if ("vqserver" >< low && "www-authenticate: basic realm=/" >< low )
    return report_finding(port:port, proto:"vqServer-admin", transport:transport);
  else if ( "1invalidrequest" >< low )
    return report_finding(port:port, proto:"mldonkey", name:"MLDonkey, a peer-to-peer client,", transport:transport);
  else if ( "get: command not found" >< low )
    return report_finding(port:port, proto:"wild_shell", name:"A shell server (possible backdoor)", transport:transport);

  else if ( "Microsoft Windows" >< banner &&
     "C:\" >< banner &&
     "(C) Copyright 1985-" >< banner &&
     "Microsoft Corp." >< banner )
    return report_finding(port:port, proto:"wild_shell", name:"A shell server (possible backdoor)", transport:transport);

  else if ( low == "root@metasploitable:/# ")
    return report_finding(port:port, proto:"wild_shell", name:"A shell server (Metasploitable)", transport:transport);

  else if ( "Tiny command server. This is a remote command server, not a telnet server." >< banner )
    return report_finding(port:port, proto:"wild_shell", name:"A shell server (rcmd.bat) from IpTools", transport:transport);

  else if ( "netbus" >< banner )
    return report_finding(port:port, proto:"netbus", name:"NetBus", transport:transport);


  else if ( "0 , 0 : error : unknown-error" >< low ||
     "0, 0: error: unknown-error" >< low ||
     "get : error : unknown-error" >< low ||
     "0 , 0 : error : invalid-port" >< low ||
           pgrep(string: low, pattern:"^[0-9]+ *, *[0-9]+ *: * userid *: *[^: ]* *:") )
    return report_finding(port:port, proto:"auth", name:"An identd server", transport:transport);

  else if ( low =~ "^http/1\." && pgrep(pattern:"^dav:.*calendar-(access|schedule|proxy)", string:low ) )
  {
    return report_finding(port:port, proto:"caldav", name:"A CalDAV server", transport:transport);
  }
  else if ( low =~ "^http/1\." && pgrep(pattern:"^dav:.*calendarserver-principal-property-search", string:low ) )
  {
    return report_finding(port:port, proto:"caldav-property", name:"A CalDAV property server", transport:transport);
  }
  else if (
     (pgrep(pattern:"^http/1\..*proxy", string:low) && !pgrep(pattern:"^cache-control:.*proxy-revalidate", string:low)) ||
     (low =~ "^http/1\." && pgrep(pattern:"^via:", string:low) ) ||
     (low =~ "^http/1\." && pgrep(pattern:"^proxy-connection: ", string:low) ) ||
     (low =~ "^http/1\." && pgrep(pattern:"^anon-proxy: ", string:low) ) ||
     #(low =~ "^http/1\." && "cache" >< low && "bad request" >< low ) ||
           # TudouVA (see BID 47508)
           ("HTTP/1.0 404 Not Found" >< banner && "Server: mmsserver" >< banner && "Allow: GET, HEAD, DELETE" >< banner && "error" >< banner)
         )
  {
    return report_finding(port:port, proto:"http_proxy", name:"An HTTP proxy", transport:transport);
  }

  else if ( low =~ "^http/1\." && "gnutella " >< low )
    return report_finding(port:port, proto:"gnutella", name:"A Gnutella servent", transport:transport);

  else if ( banner =~ "^RFB 00" )
    return report_finding(port:port, proto:"vnc", transport:transport);

  else if ( low =~ "^ncacn_http/1\." )
  {
    if ( port == 593 ) return report_finding(port:port, proto:"http-rpc-epmap", name:"An http-rpc-epmap", transport:transport);
    else return report_finding(port:port, proto:"ncacn_http", name:"An ncacn_http server", transport:transport);
  }

  else if ( 'GET / HTTP/1.0\r\n\r\n'  == banner )
    return report_finding(port:port, proto:"echo", name:"An echo server", transport:transport);

  else if ( '!"#$%&\'()*+,-./' >< banner &&
     'ABCDEFGHIJ' >< banner &&
     'abcdefg' >< banner &&
     '0123456789' >< banner ) return report_finding(port:port, proto:"chargen", transport:transport);


  else if ( "vtun server" >< low )
    return report_finding(port:port, proto:"vtun", name:"A VTUN (Virtual Tunnel) server", transport:transport);

  else if ( low == "login: password: "   ||
     ( banner =~ "^login: " && port == 540 ))
    return report_finding(port:port, proto:"uucp", transport:transport);

  else if ( low =~ "^bad request" ||
     "invalid protocol request (71): gget / http/1.0" >< low ||
     low =~ "^lpd:" ||
     "^lpsched" >< low ||
     "malformed from address" >< low ||
     "no connect permissions" >< low )
    return report_finding(port:port, proto:"lpd", name:"An LPD (Line Printer Daemon) server", transport:transport);


  else if ( "%%lyskom unsupported protocol" >< low )
    return report_finding(port:port, proto:"lyskom", transport:transport);

  else if ( "598:get:command not recognized"  >< low )
    return report_finding(port:port, proto:"ph", transport:transport);

  else if ("BitTorrent prot" >< banner )
    return report_finding(port:port, proto:"BitTorrent", name:"BitTorrent", transport:transport);

  else if ( strlen(banner) >= 3 && substr(banner, 0, 2) == 'A\x01\x02' )
    return report_finding(port:port, proto:"smux", name:"An SNMP Multiplexer (smux)", transport:transport);

  else if ( low =~ "^0 succeeded" )
    return report_finding(port:port, proto:"LISa", name:"A LISa daemon", transport:transport);


  else if ( "welcome!psybnc@" >< low ||
     "notice * :psybnc" >< low )
    return report_finding(port:port, proto:"psybnc", name:"PsyBNC (IRC proxy)", transport:transport);

  else if ( banner =~ "^\* ACAP " )
    return report_finding(port:port, proto:"acap", name:"An ACAP server", transport:transport);

  else if ( low =~ "Sorry, you ([0-9.]*) are not among the allowed hosts" )
    return report_finding(port:port, proto:"nagiosd", name:"Nagios", transport:transport);

  else if ( banner == '[TS]\nerror\n' || banner == '[TS]\r\nerror\r\n' )
    return report_finding(port:port, proto:"teamspeak-tcpquery", transport:transport);
  else if ( 'TS3 Client' >< banner && 'TeamSpeak 3 ClientQuery interface' >< banner )
    return report_finding(port:port, proto:"teamspeak3-tcpquery", transport:transport);
  else if ( banner =~ "^Language received from client: GET / HTTP/1\.0" )
    return report_finding(port:port, proto:"websm", name:"A WEBSM server", transport:transport);

  else if ( banner == "CNFGAPI" )
    return report_finding(port:port, proto:"ofa_express", name:"An OFA/Express server", transport:transport);

  else if ( banner =~ "^SuSE Meta pppd" )
    return report_finding(port:port, proto:"smppd", name:"A SuSE Meta pppd server", transport:transport);

  else if ( banner =~  "^ERR UNKNOWN-COMMAND" )
    return report_finding(port:port, proto:"upsmon", name:"A upsd/upsmon server", transport:transport);

  else if ( banner =~ "^connected\..*, ver: Legends" )
    return report_finding(port:port, proto:"sub7", name:"A Sub7 trojan", transport:transport);

  else if ( banner =~ "^WinShell:" )
    return report_finding(port:port, proto:"winshell", name:"A WinShell trojan", transport:transport);

  else if ( banner =~ "^SPAMD/[0-9.]*" )
    return report_finding(port:port, proto:"spamd", name:"SpamAssassin (spamd)", transport:transport);

  else if ( banner =~ "^220" && " dictd " >< low )
    return report_finding(port:port, proto:"dictd", name:"dictd, a dictionary database server,", transport:transport);

  else if ( banner =~ "^220 " && "VMware Authentication Daemon" >< banner )
    return report_finding(port:port, proto:"vmware_auth", name:"A VMware authentication daemon", transport:transport);


  else if ( low =~ "^220.* interscan version" )
    return report_finding(port:port, proto:"interscan_viruswall", name:"An InterScan VirusWall", transport:transport);

  else if ( strlen(banner) > 1 && banner[0] == '~' && banner[strlen(banner) - 1] == '~' && !isnull(strstr(banner, '}')) )
    return report_finding(port:port, proto:"pppd", name:"A PPP daemon", transport:transport);

  else if ( banner =~ "Hello, this is ([Zz]ebra|[Qq]uagga)" )
    return report_finding(port:port, proto:"zebra", name:"A zebra daemon", transport:transport);

  else if ( "NOTICE AUTH :" >< banner || "NOTICE Auth :" >< banner )
 {
   return report_finding(port:port, proto:"irc", name:"An IRC server");
 }

  else if ( "ircxpro " >< low )
    return report_finding(port:port, proto:"ircxpro_admin", name:"An IRCXPro administrative server", transport:transport);

  else if ( low =~ "^.*version report"  )
    return report_finding(port:port, proto:"gnocatan", name:"A Gnocatan game server", transport:transport);

  else if ( banner =~ "^RTSP/1\.0.*QTSS/"  )
    return report_finding(port:port, proto:"quicktime-streaming-server", name:"A Quicktime streaming server", transport:transport);
  else if ( banner =~ "^RTSP/1.0 400 " )
    return report_finding(port:port, proto:"rtsp", name:"A streaming server is running on this port", transport:transport);

  else if ( strlen(banner) > 2 && ord(banner[0]) == 0x30 && ord(banner[1]) == 0x11 && ord(banner[2]) == 0 )
    return report_finding(port:port, proto:"dameware", transport:transport);

  else if ( "stonegate firewall" >< low )
    return report_finding(port:port, proto:"SG_ClientAuth", name:"A StoneGate authentication server", transport:transport);

  else if ( low =~ "^pbmasterd" )
  {
    info = "A PowerBroker master server";

    ver = pregmatch(string:low, pattern:'^pbmasterd([0-9.-]+)@');
    if (ver)
    {
      info += ' (version ' + ver[1] + ')';
      set_kb_item(name:'pbmasterd/' + port + '/version', value:ver[1]);
    }

    return report_finding(port:port, proto:"power-broker-master", name:info, transport:transport);
  }

  else if ( low =~ "^pblocald" )
  {
    info = "A PowerBroker locald server";

    ver = pregmatch(string:low, pattern:'^pblocald([0-9.-]+)@');
    if (ver)
    {
      info += ' (version ' + ver[1] + ')';
      set_kb_item(name:'pblocald/' + port + '/version', value:ver[1]);
    }

    return report_finding(port:port, proto:"power-broker-locald", name:info, transport:transport);
  }

  else if ( low =~ "^pblogd" )
  {
    info = "A PowerBroker logd server";

    ver = pregmatch(string:low, pattern:'^pblogd([0-9.-]+)@');
    if (ver)
    {
      info += ' (version ' + ver[1] + ')';
      set_kb_item(name:'pblogd/' + port + '/version', value:ver[1]);
    }

    return report_finding(port:port, proto:"power-broker-logd", name:info, transport:transport);
  }

  else if ( low =~ "^<stream:error>invalid xml</stream:error>" )
    return report_finding(port:port, proto:"jabber", name:"jabber", transport:transport);

  else if ( low =~ "^/c -2 get ctgetoptions" )
    return report_finding(port:port, proto:"avotus_mm", name:"An avotus 'mm' server", transport:transport);

  else if ( low =~ "^error:wrong password" )
    return report_finding(port:port, proto:"pNSClient", name:"pNSClient.exe, a Nagios plugin,", transport:transport);

  else if ( banner =~ "^1000      2" )
    return report_finding(port:port, proto:"VeritasNetBackup", name:"Veritas NetBackup", transport:transport);

  else if ("the file name you specified is invalid" >< low &&
    "listserv" >< low )
    return report_finding(port:port, proto:"listserv", name:"A LISTSERV daemon", transport:transport);

  else if ( low =~ "^control password:" )
    return report_finding(port:port, proto:"FsSniffer", name:"FsSniffer, a password-stealing backdoor,", transport:transport);

  else if ( banner == "Gh0st" )
    return report_finding(port:port, proto:"ghost-rat", name:"Gh0st, a Remote Admin Tool often used as a backdoor,", transport:transport);

  else if ( low =~ "^remotenc control password:")
    return report_finding(port:port, proto:"RemoteNC", name:"RemoteNC, a backdoor trojan,", transport:transport);

  else if ( "error while loading shared libraries :" >< low )
    return report_finding(port:port, proto:"broken-inetd", name:"A broken inetd service (which can't load the shared libraries it depends on)", transport:transport);

  else if ( "A E O N I A N   D R E A M S" >< banner &&
            "R E A W A K E N E D" >< banner )
    return report_finding(port:port, proto:"aeonian-dreams", name:"A 'Aeonian Dreams' game server", transport:transport);


  else if ( "finger: GET: no such user" >< banner  ||
     "finger: /: no such user" >< banner ||
     "finger: HTTP/1.0: no such user" >< banner ||
     "Login       Name               TTY         Idle    When    Where" >< banner ||
     "Line     User" >< banner ||
     "Login name: GET" >< banner )
    return report_finding(port:port, proto:"finger", name:"A finger daemon", transport:transport);

  else if ( strlen(banner) >= 4 && ord(banner[0]) == 5 && ord(banner[1]) <= 8 && ord(banner[2]) == 0 && ord(banner[3]) <= 4 && ord(banner[1]) == strlen(banner) - 2)
    return report_finding(port:port, proto:"socks5",name:"A SOCKS5 proxy", transport:transport);
  else if ( strlen(banner) >= 4 && ord(banner[0]) == 0 && ord(banner[1]) >= 90 && ord(banner[1]) <= 93 )
    return report_finding(port:port, proto:"socks4",name:"A SOCKS4 proxy", transport:transport);
  else if ( pgrep(pattern:"^server: heimdal/[0-9.]+", string:low) )
  {
    low = ereg_replace(pattern:"^server: heimdal/([0-9.]+).*", string:pgrep(pattern:"^server: heimdal/[0-9.]+", string:low), replace:"\1");
    return report_finding(port:port, proto:"krbtgt", name:"A kerberos ticketing server (Heimdal v" + chomp(low) + ")", transport:transport);
  }
  # This looks like a broken web server; eg, it responds to GET requests with:
  # HTTP/1.1 501 Not Implemented
  # CIMError: Only POST and M-POST are implemented
  else if ( pgrep(pattern:"^cimerror: ", string:low) )
  {
    return report_finding(port:port, proto:"cim_listener", name:"A CIM Listener", transport:transport);
  }
  else if ( preg(string:low, pattern:'^http/[0-9.]+ 501 not implemented', multiline:TRUE) &&
            preg(string:low, pattern:'^server: sfchttpd', multiline:TRUE) )
  {
    return report_finding(port:port, proto:"cim_listener", name:"SBLIM Small Footprint CIM Broker", transport:transport);
  }
  else if ( banner =~ "^<<<check_mk>>>" )
  {
    return report_finding(port:port, proto:"check_mk", name:"A Check_MK agent", transport:transport);
  }
  else if ( banner =~ "Groovy Shell" &&
            'Type \'go\' to execute statements' >< banner)
  {
    return report_finding(port:port, proto:"groovy_shell", name:"Groovy Shell", transport:transport);
  }
  else if (banner =~ "^Android Console: type 'help' for a list of commands\r\nOK\r\n")
  {
    return report_finding(port:port, proto:"android_emulator_telnet", name:"An Android Emulator Telnet service", transport:transport);
  }
  else if (banner =~ '^\\(error "-3: \\([^)]+\\): Command not supported"\\)')
  {
    return report_finding(port:port, proto:"cogent_datahub_mirror", name:"Cogent DataHub Tunnel/Mirror service", transport:transport);
  }
  else if (
   "ViPER Monitor Transport Protocol" >< banner &&
   "ViPERManager" >< banner
  )
  {
    # May be associated with Mitel ViPER virtual cards for giving IP addresses to legacy devices.
    return report_finding(port:port, proto:"vmtp", name:"A ViPER Monitor Transport Protocol (VMTP) service", transport:transport);
  }
  else if (
    banner == '0 {}\r\n' ||
    banner == '0 {}\n'
  )
  {
    return report_finding(port:port, proto:"3par_mgmt", name:"HP 3PAR Management Service", transport:transport);
  }
  else if (
    'FSAE server' >< banner &&
    'FSAE_SERVER_' >< banner &&
    getdword(blob:banner, pos:0) == strlen(banner))
  {
    report_finding(port:port, proto:"fsae_server", name:"Fortinet Server Authentication Agent", transport:transport);
  }
  else if (banner =~ '^SRS:Ready')
  {
    return report_finding(port:port, proto:"splashtop_streamer", name:"Splashtop Streamer service", transport:transport);
  }
  else if (preg(string:banner, pattern:'^220 *\\*+\r\n'))
  {
    set_kb_item(name:"Services/filtered", value:port);
    return report_finding(port:port, proto:"cisco_pix_filtered_smtp", name:"An SMTP service filtered by Cisco PIX", transport:transport);
  }
  else if ( is_http != 1 )
    return register_unknown(port:port, banner:banner);

  return NULL;
}

#------------------#
# Banner Grabbing  #
#------------------#

function ssl_ports_init()
{
  var item;

  g_ssl_ports_H = make_array();

  foreach item ( g_ssl_ports ) g_ssl_ports_H[item] = TRUE;
}


#
# Functions definitions
#

function should_try_ssl()
{
  var port, s, e;

  if ( SSL_PORT_TO_CONNECT == SSL_CONNECT_ALL ) return TRUE;
  else if ( SSL_PORT_TO_CONNECT == SSL_CONNECT_NONE ) return FALSE;

  port = _FCT_ANON_ARGS[0];

  if ( g_ssl_ports_H[port] == TRUE ) return TRUE;

  return FALSE;
}

function port_push()
{
  if ( _FCT_ANON_ARGS[0] == 139 || _FCT_ANON_ARGS[0] == 445 || _FCT_ANON_ARGS[0] == 3389 ) return NULL; # Do not scan port 139, 445 or 3389
  # display("Push ", _FCT_ANON_ARGS[0], "\n");
  g_port_pool[g_port_pool_max++] = _FCT_ANON_ARGS[0];
}

function port_pop()
{
  if ( g_port_pool_idx >= g_port_pool_max ) return NULL;
  else return g_port_pool[g_port_pool_idx++];
}

function port_new()
{
  var port, banner, port_start_time;

  port = port_pop();
  if ( port == NULL ) return FALSE;

  g_port_start_time[port] = gettimeofday();
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
    'Port ' + port + ' tests starting...');

  #
  # Check whether nessus_tcp_scanner found the banner already
  #
  banner = get_kb_item("BannerHex/" + port);
  if ( isnull(banner) ) banner = get_kb_item( "Banner/" + port );
  else banner = hex2raw(s:banner);

  if ( should_try_ssl(port) == FALSE )
    g_transport_state[port] = E_STATE_IP;
  else
    g_transport_state[port] = E_STATE_SSL_START;

  set_sock_state(port:port, state:S_STATE_CONNECTING);
  g_methods[port] = "spontaneous";

  if ( ! isnull(banner) )
  {
    if ( is_ssl_banner(banner) && SSL_PORT_TO_CONNECT != SSL_CONNECT_NONE )
    {
      # This looks like SSL - let's force a negotiation here
      g_transport_state[port] = E_STATE_SSL_START;
    }
    else
    {
      g_transport_state[port] = E_STATE_IP;
      set_sock_state(port:port, state:S_STATE_DONE);
      g_banners[port] = banner;
      replace_kb_item(name:"Transports/TCP/" + port, value:ENCAPS_IP);
      return port_new();
    }
  }

  g_timestamps[port] = unixtime();
  if ( g_sock[port] > 0 )
  {
    close(g_sock[port]);
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Closed socket to port ' + port);
  }
  g_sock[port] = open_sock_tcp(port, transport:state_to_transport[g_transport_state[port]], nonblocking:TRUE);
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
    'Opened socket to port ' + port);

  return TRUE;
}

function port_done()
{
  var port;

  port = _FCT_ANON_ARGS[0];

  set_sock_state(port:port, state:S_STATE_DONE);
  close(g_sock[port]);

  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
    'Closed socket to port ' + port);
  g_sock[port] = NULL;

  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
    'Port ' + port + ' tests completed in ' + timediff(g_port_start_time[port]) + ' seconds');

  if (g_sock_conn_tries[port] > 0)
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Port ' + port + ' took ' + g_sock_conn_tries[port] + ' connection tries before completing.');

  port_new();
}

function mark_wrapped_svc()
{
  var port;

  port = _FCT_ANON_ARGS[0];
  if ( port == 514 ) return NULL;
  security_note(port:port, extra:'The service closed the connection without sending any data.\nIt might be protected by some sort of TCP wrapper.');
  set_kb_item(name:"Services/wrapped", value:port);
}

function port_connect_error()
{
  var port, port_start_time;

  port = _FCT_ANON_ARGS[0];
  port_start_time = gettimeofday();
  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
    'Port ' + port + ' test starting...');
  if ( g_transport_state[port] < E_STATE_IP )
  {
    transition_state(port:port);
    set_sock_state(port:port, state:S_STATE_CONNECTING);
    g_timestamps[port] = unixtime();
    if ( g_sock[port] > 0 )
    {
      close(g_sock[port]);
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
        'Closed socket to port ' + port);
    }
    g_sock[port] = open_sock_tcp(port, transport:state_to_transport[g_transport_state[port]], nonblocking:TRUE);
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
        'Opened socket to port ' + port);
  }
  else
    port_done(port);

  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
    'Port ' + port + ' test completed in ' + timediff(port_start_time) + ' seconds');
}

#
# e = error from socket_get_error()
#
function port_process(port, e)
{
  var note, ver, port_start_time;

  port_start_time = gettimeofday();
  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
    'Port ' + port + ' test starting...');

  if ( e < 0 )
  {
    if ( g_transport_state[port] < E_STATE_IP )
    {
      transition_state(port:port);
      set_sock_state(port:port, state:S_STATE_CONNECTING);
      g_timestamps[port] = unixtime();
      if ( g_sock[port] > 0 )
      {
        close(g_sock[port]);
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
          'Closed socket to port ' + port);
      }
      g_sock[port] = open_sock_tcp(port, transport:state_to_transport[g_transport_state[port]], nonblocking:TRUE);
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
        'Opened socket to port ' + port);
    }
    else port_done(port);
  }
  else
  {
    if ( (g_transport_state[port] == E_STATE_TLSv11 && !TLSv1_1_AVAILABLE) ||
         (g_transport_state[port] == E_STATE_TLSv12 && !TLSv1_2_AVAILABLE) ||
         (g_transport_state[port] == E_STATE_TLSv13 && !TLSv1_3_AVAILABLE) ||
          g_transport_state[port] == E_STATE_TLS_HELLO ||
          g_transport_state[port] == E_STATE_SSL3_HELLO ||
          g_transport_state[port] == E_STATE_SSL2_HELLO)
    {
      if (get_kb_item("global_settings/disable_ssl_cipher_neg"))
      {
        # don't fail it since it didn't attempt a connection. just let the
        # state transitions work it out.
        transition_state(port:port);
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
          'Port ' + port + ' test completed in ' + timediff(port_start_time) + ' seconds');

        return 1;
      }
      ver = SSL_hello(port:port);
      if ( ver > 0 )
      {
        note = '';
        set_sock_state(port:port, state:S_STATE_DONE);

        set_kb_item(name:"Transport/SSL", value:port);

        # Do *NOT* set Transport/TCP/<port> here as the engine does not support TLSv1.1+

        # These KBs are set by ssl_supported_versions.nasl, why set here?
        #if (  g_transport_state[port] == E_STATE_TLSv11 )
        #  set_kb_item(name:"SSL/Transport/" + port, value:COMPAT_ENCAPS_TLSv11);
        #else
        #  set_kb_item(name:"SSL/Transport/" + port, value:COMPAT_ENCAPS_TLSv12);

        if ( ver == TLS_11 ) note = 'A TLSv1.1';
        else if (ver == TLS_12 ) note = 'A TLSv1.2';
        else if (ver == TLS_13 ) note = 'A TLSv1.3';
        else if (ver == TLS_10 ) note = 'A TLSv1';
        else if (ver == SSL_V3 ) note = 'A SSLv3';
        else if (ver == SSL_V2 ) note = 'A SSLv2';
        if ( strlen(note) > 0 )
        {
          note = note + ' server answered on this port.\n';
          security_note(port:port, extra:note);
        }
        port_done(port);
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
          'Port ' + port + ' test completed in ' + timediff(port_start_time) + ' seconds');

        return NULL;
      }
      else
      {
        transition_state(port:port);
        set_sock_state(port:port, state:S_STATE_CONNECTING);
        g_timestamps[port] = unixtime();
        if ( g_sock[port] > 0 )
        {
          close(g_sock[port]);
          dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
            'Closed socket to port ' + port);
        }
        g_sock[port] = open_sock_tcp(port, transport:state_to_transport[g_transport_state[port]], nonblocking:TRUE);
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
          'Opened socket to port ' + port);
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
          'Port ' + port + ' test completed in ' + timediff(port_start_time) + ' seconds');

        return NULL;
      }
    }
    # We are connected
    replace_kb_item(name:"Transports/TCP/" + port, value:state_to_transport[g_transport_state[port]]);
    if( state_to_transport[g_transport_state[port]] != ENCAPS_IP )
    {
      set_kb_item(name:"Transport/SSL", value:port);
      if ( state_to_transport[g_transport_state[port]] == ENCAPS_SSLv2 ) note ='An SSLv2';
      else if ( state_to_transport[g_transport_state[port]] == ENCAPS_SSLv3 ) note ='An SSLv3';
      else if ( state_to_transport[g_transport_state[port]] == ENCAPS_TLSv1 ) note ='A TLSv1';
      else if ( state_to_transport[g_transport_state[port]] == COMPAT_ENCAPS_TLSv11 ) note ='A TLSv1.1';
      else if ( state_to_transport[g_transport_state[port]] == COMPAT_ENCAPS_TLSv12 ) note ='A TLSv1.2';
      else if ( state_to_transport[g_transport_state[port]] == COMPAT_ENCAPS_TLSv13 ) note ='A TLSv1.3';
      else note = NULL;
      if ( note )
      {
        note = note + ' server answered on this port.\n';
        security_note(port:port, extra:note);
      }
    }
    set_sock_state(port:port, state:S_STATE_READING);
  }
  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
    'Port ' + port + ' test completed in ' + timediff(port_start_time) + ' seconds');

  return 1;
}

function port_send_get()
{
  var port, port_start_time;

  port = _FCT_ANON_ARGS[0];

  port_start_time = gettimeofday();
  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
    'Port ' + port + ' test starting...');

  send(socket:g_sock[port], data:'GET / HTTP/1.0\r\n\r\n');
  set_sock_state(port:port, state:S_STATE_READING_W_GET);
  g_methods[port] = "get_http";

  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
    'Port ' + port + ' test completed in ' + timediff(port_start_time) + ' seconds');
}

##
# Set the state and log if debugging is enabled
#
# @param [port:integer] port number
# @param [state:integer] state as a constant variable (e.g. S_STATE_CONNECTING, S_STATE_READING_W_GET)
#
# @remark modifies global variable g_sock_state
#
# @return NULL always
##
function set_sock_state(port, state)
{
  if (get_kb_item("global_settings/enable_plugin_debugging"))
  {
    var current_state = g_sock_state[port];

    if (empty_or_null(current_state))
    {
      g_port_state_time[port] = gettimeofday();
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
        'Port ' + port + ' state ' + S_STATE_DESCRIPTIONS[state] + ' starting...');
    }

    # State change
    else if (state != current_state)
    {
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
        'Port ' + port + ' state ' + S_STATE_DESCRIPTIONS[state] + ' completed in ' + timediff(g_port_state_time[port]) + ' seconds');

      if (state == S_STATE_DONE)
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
          'Port ' + port + ' state set to S_STATE_DONE.');
      else
      {
        g_port_state_time[port] = gettimeofday();
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
          'Port ' + port + ' state ' + S_STATE_DESCRIPTIONS[state] + ' starting...');
      }
    }
  }

  g_sock_state[port] = state;
}

function select()
{
  var port, now, e, e2, num, state;

  num = 0;
  now = unixtime();

  foreach port ( keys(g_sock) )
  {
    if ( g_sock_state[port] == S_STATE_CONNECTING )
    {
      num ++;
      e =  socket_get_error(g_sock[port]);
      if ( e != 0 && e != EINPROGRESS )
      {
        if ( e == ECONNREFUSED )
        {
          dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
            'Connection refused on port ' + port);
          port_done(port);
        }
        else port_connect_error(port); # Some error occurred
      }

      e2 = socket_ready(g_sock[port]);
      if ( e2 > 0 )
      {
        if(isnull(port_process(port:port, e:e)))
          g_sock_conn_tries[port] ++;
        if(g_sock_conn_tries[port] > CONNECT_RETRIES)
          num --;
      }
      else if ( e2 == 0 && (socket_get_error(g_sock[port]) != 0 &&
       socket_get_error(g_sock[port]) != EINPROGRESS) ) port_connect_error(port);
      else if ( e2 < 0 || (now - g_timestamps[port] >= CONNECT_TIMEOUT) ) port_connect_error(port);
    }
    else if ( g_sock_state[port] == S_STATE_READING )
    {
      num ++;
      g_sock_conn_tries[port] = 0;
      if ( socket_pending(g_sock[port]) )
      {
        g_banners[port] = recv(socket:g_sock[port], length:65535);
        #display(hexstr(g_banners[port]), "\n");
        if ( isnull(g_banners[port]) && socket_get_error(g_sock[port]) == ECONNRESET )
          mark_wrapped_svc(port);
        else if ( isnull(g_banners[port]) && socket_get_error(g_sock[port]) == ETIMEDOUT)
        {
          port_send_get(port);
          continue;
        }
        else if ( isnull(g_banners[port]) )
          register_unknown(port:port, banner:NULL);

        port_done(port);
      }
      else if ( now - g_timestamps[port] >= SPONTANEOUS_TIMEOUT )
        port_send_get(port);
    }
    else if ( g_sock_state[port] == S_STATE_READING_W_GET )
    {
      num ++;
      g_sock_conn_tries[port] = 0;
      if ( socket_pending(g_sock[port]) )
      {
        g_banners[port] = recv(socket:g_sock[port], length:65535);
        #display(hexstr(g_banners[port]), "\n");
        if ( g_banners[port] == NULL ) register_unknown(port:port, banner:NULL);
        port_done(port);
      }
      else if ( now - g_timestamps[port] >= TIMEOUT)
      {
        register_unknown(port:port, banner:NULL);
        register_silent(port);
        port_done(port);
      }
    }
  }

  return num;
}

#-----------#
# Main      #
#-----------#

function main()
{
  var list, item, i, port, pref, rt, to2, k;
  var execution_start_time, select_start_time;

  execution_start_time = gettimeofday();
  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
    'execution starting...');

  rt = get_read_timeout();

  pref = int(get_preference("max_checks"));
  if (pref > 0)
  {
    MAX_SIMULT_CONNECTIONS = pref;
    if (islocalnet())
      MAX_SIMULT_CONNECTIONS *= 2;
    else
    {
      # Congestion information in KB is not reliable in 4.0.1 or earlier
      pref = int(get_preference("TCPScanner/NbPasses"));
      if (pref <= 0) pref = int(get_preference("SYNScanner/NbPasses"));
      if (pref > 0 && pref <= 2) pref *= 2;
    }
  }
  # Just in case..
  foreach k (["max_simult_tcp_sessions", "global.max_simult_tcp_sessions", "host.max_simult_tcp_sessions"])
  {
    pref = int(get_preference(k));
    if (pref > 0 && MAX_SIMULT_CONNECTIONS > pref)
      MAX_SIMULT_CONNECTIONS = pref;
  }

  if ( MAX_SIMULT_CONNECTIONS > 32 ) MAX_SIMULT_CONNECTIONS = 32;
  set_kb_item(name: "FindService/MaxSimultCnx", value: MAX_SIMULT_CONNECTIONS);
  if (rt > 30)
    to2 = rt;
  else
  {
    to2 = 2 * rt;
    if (to2 > 30) to2 = 30;
   }

  CONNECT_TIMEOUT = to2;
  TIMEOUT = to2;

  pref = get_preference("Test SSL based services");

  # Changed preference name to support .nessus policy import, but policies using the old
  # name are still out there.
  if(isnull(pref))
  {
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'New preference returned NULL.  Trying legacy preference.');
    pref = script_get_preference("Test SSL based services");
  }

  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
    'TLS discovery preference is: ' + pref);
  if ( "All" >< pref )
  {
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Detecting TLS on all discovered ports.');
    SSL_PORT_TO_CONNECT = SSL_CONNECT_ALL;
  }
  else if ( "None" >< pref )
  {
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Not performing TLS service discovery.');
    SSL_PORT_TO_CONNECT = SSL_CONNECT_NONE;
    set_kb_item(name:"global_settings/disable_test_ssl_based_services", value:TRUE);
  }
  else if ( "Known" >< pref )
  {
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Checking for TLS services only on ports known to host them.');
    SSL_PORT_TO_CONNECT = SSL_CONNECT_KNOWN;
  }
  else
  {
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Unrecognized TLS service discovery setting.  Defaulting to \'All ports\'.');
    SSL_PORT_TO_CONNECT = SSL_CONNECT_ALL;
  }

  list = get_kb_list("Ports/tcp/*");
  if ( isnull(list) )
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
      'Plugin exited, no Ports/tcp/*');
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
      'execution completed in ' + timediff(execution_start_time) + ' seconds');

    exit(0, "No open ports were detected."); # No open port
  }
  list = keys(list);
  if ( max_index(list) > 1500 )
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
      'Plugin exited, Too many open ports.');
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
      'execution completed in ' + timediff(execution_start_time) + ' seconds');

    exit(1, "Too many open ports.");
  }
  dbg::detailed_log(
    lvl:3,
    src:FUNCTION_NAME,
    msg:'Ports list',
    msg_details:{
       "Value":{"lvl":3, "value":obj_rep(list)}
    });
  foreach item (list)
  {
    if (service_is_unknown(port:int(item - "Ports/tcp/")) )
      port_push(int(item - "Ports/tcp/"));
  }

  for ( i = 0 ; i < MAX_SIMULT_CONNECTIONS ; i ++ )
    if ( port_new() == FALSE ) break;

  select_start_time = gettimeofday();
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
    'select() loop starting...');
  while ( select() != 0 ) usleep(5000);
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
    'select() loop completed in ' + timediff(select_start_time) + ' seconds');

  foreach port ( keys(g_banners) )
  {
    if ( isnull(g_banners[port]) )
    {
      register_unknown(port:port, banner:NULL);
      continue;
    }
    #display(hexstr(g_banners[port]), "\n");
    set_kb_banner(port: port, type: g_methods[port], banner: g_banners[port]);
    three_digits(port:port, banner:g_banners[port]);
    recognize_banner(banner:g_banners[port], port:port, transport:state_to_transport[g_transport_state[port]]);
  }
  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
    'execution completed in ' + timediff(execution_start_time) + ' seconds');
}

#
# This function goes through every service which showed an SSL error when
# being connected to, and forces a SSL negotiation on these.
#
function try_non_std_ssl_ports()
{
  var i, port, select_start_time;

  dbg::detailed_log(
    lvl:3,
    src:FUNCTION_NAME,
    msg:'g_ssl_ports_to_try',
    msg_details:{
       "value":{"lvl":3, "value":obj_rep(g_ssl_ports_to_try)}
    });
  if ( g_ssl_ports_to_try_idx == 0 ) return NULL;
  if (get_kb_item("global_settings/disable_ssl_cipher_neg")) return NULL;

  #
  # Reset globals
  #
  globals_reset();

  #
  # Mark all ports to be SSL compatible
  #
  SSL_PORT_TO_CONNECT = SSL_CONNECT_ALL;

  for ( i = 0 ; i < g_ssl_ports_to_try_idx ; i ++ )
    port_push(g_ssl_ports_to_try[i]);

  for ( i = 0 ; i < MAX_SIMULT_CONNECTIONS ; i ++ )
    if ( port_new() == FALSE ) break;

  select_start_time = gettimeofday();
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
    'select() loop starting...');
  while ( select() != 0 ) usleep(5000);
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
    'select() loop completed in ' + timediff(select_start_time) + ' seconds');

  foreach port ( keys(g_banners) )
  {
    if ( isnull(g_banners[port]) ) continue;
    set_kb_banner(port: port, type: g_methods[port], banner: g_banners[port]);
    three_digits(port:port, banner:g_banners[port]);
    recognize_banner(banner:g_banners[port], port:port, transport:state_to_transport[g_transport_state[port]]);
  }
}

if (nessusd_is_agent())
{
  exit(0, 'This plugin does not run on Nessus Agents');
}


var script_start_time = gettimeofday();
dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:
  'starting...');

globals_init();
ssl_ports_init();
main();
try_non_std_ssl_ports();

dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:
  'completed in ' + timediff(script_start_time) + ' seconds');
