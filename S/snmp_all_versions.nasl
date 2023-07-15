#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(40448);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/06");

  script_name(english:"SNMP Supported Protocols Detection");
  script_summary(english:"Reports all supported SNMP versions.");

  script_set_attribute( attribute:'synopsis', value:
"This plugin reports all the protocol versions successfully negotiated
with the remote SNMP agent."  );
  script_set_attribute( attribute:'description', value:
"Extend the SNMP settings data already gathered by testing for\
SNMP versions other than the highest negotiated."  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/07/31' );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category( ACT_GATHER_INFO );
  script_family( english:'SNMP' );

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_require_keys( 'SNMP/community', 'SNMP/community_v1_v2c', 'SNMP/version' );
  exit(0);
}

include ('misc_func.inc');
include ('snmp_func.inc');


function do_initial_snmp_get (community, port)
{

  local_var soc, result;
  soc = open_sock_udp(port);

  if (! soc)
    audit(AUDIT_SOCK_FAIL, port, 'UDP');

  result = snmp_request(socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0", timeout:2);
  close(soc);

  return result;
}


# Real check for snmpv3 existence. Other plugins are marking
# the protocol version as failed if we cannot auth. This plugin
# is interested in marking the protocl as present regardless
# of auth status (and having no effect on anything else).
function check_for_snmpv3 (port)
{

  local_var local_copy_of_global_msg_id = 0;
  local_var msg_global_data = NULL;
  local_var authentication_data = NULL;
  local_var data_to_send = NULL;
  local_var snmp_header = NULL;
  local_var request = NULL;
  local_var sock = NULL;
  local_var rep = NULL;

  dbg::detailed_log(lvl:1, src:'check_for_snmpv3',
    msg:'Entering check_for_snmpv3',
    msg_details:{
      'port':{'lvl':1, value:port}
    });

  set_snmp_version(version:3);

  # save a copy of a global var that should not be global
  local_copy_of_global_msg_id = msg_id;
  msg_id = rand();

  sock = open_sock_udp(port);
  if (!sock)
  {
    # restore global var that should not be a global var
    msg_id = local_copy_of_global_msg_id;

    dbg::detailed_log(lvl:1, src:'check_for_snmpv3',
       msg:'Could not open UDP socket. Returning FALSE.',
       msg_details:{
         'port':{'lvl':1, value:port}
       });
    return FALSE;
  }

  msg_global_data = snmpv3_put_msg_global_data(
    msg_max_size       : MSG_MAX_SIZE,
    msg_flags          : raw_string(MSG_REPORTABLE_FLAG),
    msg_security_model : USM_SECURITY_MODEL);


  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'Creating msg_global_data',
    msg_details:{
      'MSG_MAX_SIZE':{'lvl':3, 'value':MSG_MAX_SIZE},
      'MSG_REPORTABLE_FLAG':{'lvl':3, 'value':MSG_REPORTABLE_FLAG},
      'USM_SECURITY_MODEL':{'lvl':3, 'value':USM_SECURITY_MODEL},
      'Data':{'lvl':3, 'value':msg_global_data}
    });

  authentication_data = snmp_assemble_authentication_data(
    auth_engine_data : snmp_put_engine_data(),
    msg_user_name    : '',
    msg_auth_param   : string (0),
    msg_priv_param   : NULL);

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'Creating authentication_data',
    msg_details:{
      'Data':{'lvl':3, 'value':msg_global_data}
    });

  snmp_header = raw_string(
    ber_put_int(i: 3),
    msg_global_data,
    authentication_data);

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'Creating snmp_header',
    msg_details:{
      'Data':{'lvl':3, 'value':snmp_header}
    });

  request = snmp_assemble_request_data(
    seq : make_list(),
    op  : OP_GET_REQUEST);

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'Creating request',
    msg_details:{
      'Data':{'lvl':3, 'value':request}
    });

  data_to_send = ber_put_sequence(seq:make_list(snmp_header, request));

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'SEND',
    msg_details:{
      'Data':{'lvl':3, 'value':data_to_send}
    });

  send(
    socket : sock,
    data   : data_to_send);

  rep = snmp_reply(
    socket  : sock,
    timeout : 100,
    ret_err : TRUE);

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'RECV',
    msg_details:{
      'Data':{'lvl':3, 'value':rep}
    });

  close(sock);

  # restore global snmp version data that should not be global
  reset_snmp_version();

  # restore global var that should not be a global var
  msg_id = local_copy_of_global_msg_id;

  if (empty_or_null(rep))
  {
    dbg::detailed_log(lvl:1, src:'check_for_snmpv3',
       msg:'Did not receive reply. Returning FALSE',
       msg_details:{
         'port':{'lvl':1, value:port}
       });

    return FALSE;
  }
  else
  {
    dbg::detailed_log(lvl:1, src:'check_for_snmpv3',
       msg:'Returning TRUE',
       msg_details:{
         'port':{'lvl':1, value:port}
       });

    return TRUE;
  }
}


supported = make_list(0, 0, 0, 0 );

v3_supported = get_kb_item('SNMP/v3/Supported');
community_v1_v2c = get_kb_item('SNMP/community_v1_v2c');
version = get_kb_item('SNMP/version');

port = get_kb_item('SNMP/port');
if (!port)
   port = 161;

if (empty_or_null(v3_supported))
  v3_supported = check_for_snmpv3(port:port);

# We already know that this version works.
# Where 'this version' is whatever the KB has
# in SNMP/version. A value that it set elsewhere.
if  (!isnull(version) && version <= 3)
  supported[version] = 1;

# We have detected presense of SNMPv3, let's try for SNMPv1/2c
if (v3_supported)
{
  supported[3] = 1;
  set_snmp_version(version:1); # SNMPv2c
  res = do_initial_snmp_get(community:community_v1_v2c, port:port);

  if  (!isnull(res))
    supported[SNMP_VERSION] = 1;

  reset_snmp_version();

  set_snmp_version(version:0); # SNMPv1
  res = do_initial_snmp_get(community:community_v1_v2c, port:port);

  if  (!isnull(res))
    supported[SNMP_VERSION] = 1;

  reset_snmp_version();
}

# Otherwise, we've found a community string that works
# We already know if v3 works from v3_supported,
# But, there may be a lower supported version
# If version is 1, try version 0.  If version is 0, we have already tried 1 and it failed.
else if (version == 1)
{
  set_snmp_version(version:0); # SNMPv1
  res = do_initial_snmp_get(community:community_v1_v2c, port:port);

  if  (!isnull(res))
    supported[SNMP_VERSION] = 1;

  reset_snmp_version();
}

version_result = NULL;
report = '';

for (i=0; i<max_index(supported); i++ )
{
  if  (supported[i])
  {
    version_result = version_result | supported[i];
    version = 'SNMPv';
    if (i == 0)
      version += '1';
    else if(i == 1)
      version += '2c';
    else if(i == 3)
      version += '3';
    report += 'This host supports SNMP version ' +  version + '.\n';
  }
}

if (!version_result)
  audit(AUDIT_NOT_LISTEN, 'SNMP', port, 'UDP');

security_note(port:port, proto:'udp', extra:report);
