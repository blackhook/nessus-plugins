#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

MAX_ADDITIONAL_SNMP_COMMUNITIES = 3;
MAX_ADDITIONAL_SNMP_PORTS = 3;

include("compat.inc");

if (description)
{
  script_id(19762);
  script_version("1.32");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_name(english:"SNMP settings");
  script_summary(english:"Sets SNMP settings.");

  script_set_attribute(attribute:"synopsis", value:"Sets SNMP settings.");
  script_set_attribute(attribute:"description", value:
"This script just sets global variables (SNMP community string and
SNMP port) and does not perform any security checks.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"Settings");

  script_add_preference(name:"Community name :", type:"entry", value:"public");
  for ( var i = 1 ; i <= MAX_ADDITIONAL_SNMP_COMMUNITIES ; i ++ )
    script_add_preference(name:"Community name (" + i + ") :", type:"entry", value:"");

  script_add_preference(name:"UDP port :", type:"entry", value:"161");
  for ( i = 1 ; i <= MAX_ADDITIONAL_SNMP_PORTS ; i ++ )
    script_add_preference(name:"Additional UDP port (" + i + ") :", type:"entry", value:"");

  script_add_preference(name:"SNMPv3 user name :", type:"entry", value:"");
  script_add_preference(name:"SNMPv3 authentication password :", type:"password", value:"");
  script_add_preference(name:"SNMPv3 authentication algorithm :", type:"radio", value:"MD5;SHA1");
  script_add_preference(name:"SNMPv3 privacy password :", type:"password", value:"");
  script_add_preference(name:"SNMPv3 privacy algorithm :", type:"radio", value:"AES;DES");
  for ( i = 1 ; i <= 5 ; i ++ )
  {
    script_add_preference(name:"SNMPv3 user name (" + i + ") : ",
                          type:"entry",
                          value:"");
    script_add_preference(name:"SNMPv3 authentication algorithm (" + i + ") : ",
                          type:"radio",
                          value:"MD5;SHA1");
    script_add_preference(name:"SNMPv3 privacy algorithm (" + i + ") : ",
                          type:"radio",
                          value:"AES;DES");
  }
  exit(0);
}
include ("snmp_func.inc");
include ("spad_log_func.inc");

snmp_port = 0;

function skip_check()
{
  var policy_name = get_preference('@internal@policy_name'); # =Host Discovery
  var fast_discovery = get_preference('Ping the remote host[checkbox]:Fast network discovery'); # =no
  var discovery_mode = get_preference('discovery_mode'); # =custom
  var syn_scan_status = get_preference('plugin_selection.individual_plugin.11219'); # =disabled
  var udp_scan_status = get_preference('plugin_selection.individual_plugin.34277'); # =disabled
  var dont_scan_printers = get_preference('Do not scan fragile devices[checkbox]:Scan Network Printers'); # =no
  var netstat_snmp = get_preference('local_portscan.snmp'); # =no
  if(policy_name == 'Host Discovery' &&
      discovery_mode == 'custom' &&
      dont_scan_printers == 'no' &&
      (isnull(netstat_snmp) || netstat_snmp == 'no') &&
      fast_discovery == 'no' &&
      syn_scan_status = 'disabled' &&
      udp_scan_status = 'disabled')
    return TRUE;

  return FALSE;
}

function do_initial_snmp_get( community, ports )
{
  local_var port, soc, index;

  if (isnull(community) || strlen(community) == 0) return NULL;

  foreach port (ports)
  {
    soc = open_sock_udp(port);
    if (soc)
    {
      index = snmp_request_next(socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0", timeout:2);
      close(soc);

      if (
        !isnull(index) &&
        # Sun ...
        index[1] != "/var/snmp/snmpdx.st" &&
        index[1] != "/etc/snmp/conf" &&
        # HP MSL 8048
        index[0] != "1.3.6.1.2.1.11.6.0"
      )
      {
        snmp_port = port;
        return index;
      }
    }
  }
  return NULL;
}

if(skip_check())
  exit(0, 'Plugin pulled in through dependencies, check is not necessary.');

index = community = NULL;

p = script_get_preference("UDP port :");
if (!p) p = 161;
ports = make_list(p);

for (i=1; i<=MAX_ADDITIONAL_SNMP_PORTS; i++)
{
  p = script_get_preference("Additional UDP port (" + i + ") :");
  if (!isnull(p))
  {
    p = int(p);
    if (p >= 1 && p <= 65535) ports = make_list(ports, p);
  }
}
ports = list_uniq(ports);


# SNMPv3
var snmpv3_array_list = [];
var snmpv3_user = script_get_preference("SNMPv3 user name :");
var snmpv3_auth = script_get_preference("SNMPv3 authentication password :");
var snmpv3_aalg = script_get_preference("SNMPv3 authentication algorithm :");
var snmpv3_priv = script_get_preference("SNMPv3 privacy password :");
var snmpv3_palg = script_get_preference("SNMPv3 privacy algorithm :");
var snmpv3_port = script_get_preference("SNMPv3 port :");

if (!empty_or_null(snmpv3_user))
{
  # replace_kb_item this one later when we actually test the credentials
  set_kb_item( name:"SNMP/v3/username", value:snmpv3_user );
  append_element(var:snmpv3_array_list, value:{
    "username": snmpv3_user,
    "authpass": snmpv3_auth,
    "authalg":  snmpv3_aalg,
    "privpass": snmpv3_priv,
    "privalg":  snmpv3_palg,
    "port":     snmpv3_port
  });
}

for (var i = 1; i <= 100; i++)
{
  snmpv3_user = script_get_preference("SNMPv3 user name (" + i + ") :");
  if (empty_or_null(snmpv3_user)) break;
  snmpv3_auth = script_get_preference("SNMPv3 authentication password (" + i + ") :");
  snmpv3_aalg = script_get_preference("SNMPv3 authentication algorithm (" + i + ") :");
  snmpv3_priv = script_get_preference("SNMPv3 privacy password (" + i + ") :");
  snmpv3_palg = script_get_preference("SNMPv3 privacy algorithm (" + i + ") :");
  snmpv3_port = script_get_preference("SNMPv3 port (" + i + ") :");
  if (!empty_or_null(snmpv3_user))
  {
    append_element(var:snmpv3_array_list, value:{
      "username": snmpv3_user,
      "authpass": snmpv3_auth,
      "authalg":  snmpv3_aalg,
      "privpass": snmpv3_priv,
      "privalg":  snmpv3_palg,
      "port":     snmpv3_port
    });
  }
}

foreach var snmpv3_creds (snmpv3_array_list)
{
  # Zero out internal snmpv3 values so we aren't operating against old data
  creds = make_list( '', '', '', '', '', '' );
  rm_kb_item(name:'SNMP/v3/LocalizedAuthKey');
  rm_kb_item(name:'SNMP/v3/LocalizedPrivKey');

  snmpv3_user = snmpv3_creds["username"];
  snmpv3_auth = snmpv3_creds["authpass"];
  snmpv3_aalg = snmpv3_creds["authalg"];
  snmpv3_priv = snmpv3_creds["privpass"];
  snmpv3_palg = snmpv3_creds["privalg"];
  snmpv3_port = snmpv3_creds["port"];

  # set defaults for Nessus < 6.x and SC < 5.x
  # Nessus will send the default value as the entire list (e.g. "MD5;SHA1")
  # SC will send the default as the empty string
  if ('MD5' >< snmpv3_aalg || snmpv3_aalg == '')
    snmpv3_aalg = 'MD5';
  if ('AES' >< snmpv3_palg || snmpv3_palg == '')
    snmpv3_palg = 'AES';
  
  # Determine what level of SNMPv3 authentication has been requested.
  if  ( snmpv3_user && snmpv3_auth && snmpv3_aalg && snmpv3_priv && snmpv3_palg )
    snmpv3_security_level = USM_LEVEL_AUTH_PRIV;   # authPriv
  else if  ( snmpv3_user && snmpv3_auth && snmpv3_aalg )
    snmpv3_security_level = USM_LEVEL_AUTH_NO_PRIV;   # authNoPriv
  else
    snmpv3_security_level = USM_LEVEL_NO_AUTH_NO_PRIV;   # noAuthNoPriv

  auth_blob = base64( str:snmpv3_user + ';'+
                          snmpv3_auth + ';'+
                          snmpv3_aalg + ';'+
                          snmpv3_priv + ';'+
                          snmpv3_palg + ';'+
                          snmpv3_security_level );
  community = ';' + auth_blob;
  SNMP_VERSION = 3; # SNMPv3

  snmpv3_ports = ports;
  if (snmpv3_port)
    snmpv3_ports = [snmpv3_port];
  index = do_initial_snmp_get(community:community, ports:snmpv3_ports);
  if (!isnull(index))
  {
    # Successful SNMPv3 connection
    replace_kb_item(name:"SNMP/v3/username", value:snmpv3_user );
    break;
  }
}

community_names = make_list();
community_v1_v2c = script_get_preference( 'Community name :' );

if (empty_or_null(community_v1_v2c))
{
  community_v1_v2c = "public";
  set_kb_item(name:"SNMP/public/default", value:TRUE);
}
else
{
  set_kb_item(name:'SNMP/community_name/0', value:community_v1_v2c);
  community_names = make_list(community_names, community_v1_v2c);

  community_name = '';
  for (i = 1; i <= MAX_ADDITIONAL_SNMP_COMMUNITIES; i++)
  {
    community_name = '';
    community_name = script_get_preference( 'Community name (' + i + ') :' );
    if (!empty_or_null(community_name))
    {
      community_names = make_list(community_names, community_name);
      set_kb_item(name:'SNMP/community_name/'+i, value:community_name);
    }
  }
}

if (isnull(index))
{
  set_kb_item(name:"SNMP/v3/FAILED", value:TRUE);
  SNMP_VERSION = 1; # SNMPv2c
  index = do_initial_snmp_get(community:community_v1_v2c, ports:ports);
  if  ( index )
    community = community_v1_v2c;
}

if (isnull(index))
{
  SNMP_VERSION = 0; # SNMPv1
  index = do_initial_snmp_get(community:community_v1_v2c, ports:ports);
  if  ( index )
    community = community_v1_v2c;
}

if ( isnull(index) )
{
 for ( i = 1 ; i <= MAX_ADDITIONAL_SNMP_COMMUNITIES || strlen(community_v1_v2c) > 0 ; i ++ )
 {
  community_v1_v2c = script_get_preference( 'Community name (' + i + ') :' );
  if ( strlen(community_v1_v2c) == 0 ) continue;
  SNMP_VERSION = 1; # SNMPv2c
  index = do_initial_snmp_get(community:community_v1_v2c, ports:ports);
  if ( index ) { community = community_v1_v2c ; break ; }
  SNMP_VERSION = 0; # SNMPv1
  index = do_initial_snmp_get(community:community_v1_v2c, ports:ports);
  if ( index ) { community = community_v1_v2c ; break ; }
 }
}


# snmp_port is 0 if index is null
if (isnull(index))
{
  err = '';
  # v3
  if (!empty_or_null(snmpv3_ports))
  {
    foreach var port (snmpv3_ports)
    {
      if (!get_port_state(port)) continue;
      err = 'Failed to authenticate using the supplied credentials.';
      snmp_set_kb_auth_failure(port:port, login:snmpv3_user, error:err, snmp_ver:3);
    }
  }

  # snmp < v3
#  if (!empty_or_null(ports))
#  {
#    foreach port (ports)
#    {
#      if (!get_port_state(port)) continue;
#      err = 'Failed to authenticate using the supplied community string.';
#      foreach name (community_names)
#      {
#        snmp_set_kb_auth_failure(port:port, login:name, error:err, snmp_ver:2);
#      }
#    }
#  }
  set_kb_item(name:'SNMP/auth_failed', value:TRUE);
  exit(0, "Not able to authenticate via SNMP.");
}

if (!snmp_port) exit (1, "Failed to identify the SNMP port.");

set_kb_item( name:"SNMP/community", value:community );
set_kb_item( name:"SNMP/community_v1_v2c", value:community_v1_v2c );
set_kb_item( name:"SNMP/port", value:snmp_port );
set_kb_item( name:"SNMP/version", value:SNMP_VERSION );

spad_log(message:'Successful SNMP connection with SNMP version:' + SNMP_VERSION);

if (!empty_or_null(snmpv3_ports))
  snmp_set_kb_auth_success(port:snmp_port, login:snmpv3_user, snmp_ver:3);

if(SNMP_VERSION < 3)
{
  report = 'The remote SNMP server accepts cleartext community strings.';
  set_kb_item(name:"PCI/ClearTextCreds/" + snmp_port, value:report);
}

if ( SNMP_VERSION == 0 ) set_kb_item( name:"SNMP/version_v1", value:TRUE);
register_service(port:snmp_port, proto:"snmp", ipproto:"udp");
