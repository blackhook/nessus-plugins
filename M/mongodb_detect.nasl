#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65914);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"MongoDB Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a database system.");
  script_set_attribute(attribute:"description", value:
"A document-oriented database system is listening on the remote port.");
  script_set_attribute(attribute:"see_also", value:"https://www.mongodb.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service.nasl", "ssl_cert_CN_mismatch.nasl");
  script_require_ports("Services/unknown", "Services/mongodb-http", 27017);

  exit(0);
}

include('byte_func.inc');
include('debug.inc');
include('install_func.inc');

##
# Checks for Azure Cosmos API for MongoDB by examining X509 altNames.
#
# @param [port:int] port running MongoDB
#
# @return true if detected; false otherwise
##
function check_for_cosmosdb_api(port)
{
  var x509_altNames = get_kb_list(strcat('X509/', port, '/altName'));
  foreach var x509_altName (x509_altNames)
    if (x509_altName =~ '\\.(documents|cosmos|cosmosdb)\\.azure\\.com$')
      return true;

  return false;
}

var app = 'MongoDB';
var MONGODB_PROTO = 'mongodb';
var service = MONGODB_PROTO;
var cpe = 'cpe:/a:mongodb:mongodb';

var extra = {};
var extra_no_report = {};

var port = NULL;

var mongodb_detected = FALSE;

# default listening port for mongodb
var port_list = make_list(27017);

if (
  thorough_tests &&
  !get_kb_item('global_settings/disable_service_discovery')
)
{
  var unknown_services = get_unknown_svc_list();
  port_list = make_list(port_list, unknown_services);
}

# add any mongodb wire protocols detected by GET HTTP request
var mongodb_http_port_list = get_kb_list('Services/mongodb-http');
foreach var item (mongodb_http_port_list)
{
  port_list = make_list(port_list, int(item));
}

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# filter out duplicate ports
port_list = list_uniq(port_list);

# Prepare x509 certificate information in case the response is NULL,
# to retry in SSL mode.
# An arbitrary amount of these creds exist now.
var cert_list = [];
var idx    = 0;
var sets   = 0;
var key    = 'Database';
var dbtype = get_kb_item(key+'/type');

var ca, cert, client_key, client_key_pass;

while(!isnull(dbtype))
{
  if(dbtype == 8)
  {
    ca              = get_kb_item(key+'/CA');
    cert            = get_kb_item(key+'/client_cert');
    client_key      = get_kb_item('/tmp/'+key+'/client_key');
    client_key_pass = get_kb_item('/tmp/'+key+'/client_key_pass');
    if (cert)
    {
      cert_list[sets++] = {
        'ca'          : ca,
        'cert'        : cert,
        'key'         : client_key,
        'key_pass'    : client_key_pass
      };
      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:
        'SSL Creds ingested from Database->MongoDB type');
    }
  }
  idx += 1;
  key = 'Database/'+idx;
  dbtype = get_kb_item(key+'/type');
}

# Older Miscellaneous->X.509 cred type to use in addition to current Database->Database type
ca              = get_kb_item('SSL/CA');
cert            = get_kb_item('SSL/cert');
client_key      = get_kb_item('SSL/key');
client_key_pass = get_kb_item('SSL/password');
if(cert)
{
  cert_list[sets++] = {
    'ca'        : ca,
    'cert'      : cert,
    'key'       : client_key,
    'key_pass'  : client_key_pass
  };
  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:
    'SSL Creds ingested from Misc->X.509 type');
}

var ssl_detected;

function size_encapsulate(data)
{
  return mkdword(strlen(data) + 4) + data;
}

function recv_response(sock)
{
  local_var size, data;
  data = recv(socket:sock, min:4, length:4);

  if (isnull(data) || strlen(data) != 4)
    return NULL;

  size = getdword(blob:data, pos:0);
  if(size > 10*1024*1024) return NULL;

  # message should contain some data
  if (size <= 4) return NULL;

  data = recv(socket:sock, min:size - 4, length:size - 4);

  if (isnull(data) || strlen(data) != (size - 4))
    return NULL;

  return data;
}

function build_query(collection, bson, request_id)
{
  local_var query;
  if (isnull(request_id) || strlen(request_id) != 4)
    request_id = 'ness';

  query =
  request_id + # request id (4 bytes)
  raw_string(0x00, 0x00, 0x00, 0x00) + # responseTo
  raw_string(0xd4, 0x07, 0x00, 0x00) + # query
  raw_string(0x00, 0x00, 0x00, 0x00) + # flags
  collection + raw_string(0x00) + # collection name
  raw_string(0x00, 0x00, 0x00, 0x00) + # number of records to skip
  raw_string(0xff, 0xff, 0xff, 0xff) + # number to return
  bson;
  query = size_encapsulate(data: query);

  return query;
}

dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:
  'Port list: ' + obj_rep(port_list));

# For each of the ports we want to try, fork.
port = branch(port_list);

if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

var soc = open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

var ismaster_command =
  raw_string(0x10) + # int32
  'ismaster' + raw_string(0x00) + # command
  raw_string(0x01, 0x00, 0x00, 0x00) + # 1
  raw_string(0x00); # end BSON document
ismaster_command = size_encapsulate(data: ismaster_command);

var buildinfo_command =
  raw_string(0x10) + # int32
  'buildinfo' + raw_string(0x00) + # command
  raw_string(0x01, 0x00, 0x00, 0x00) + # 1
  raw_string(0x00); # end bson document
buildinfo_command = size_encapsulate(data: buildinfo_command);

var listDatabases_command =
  raw_string(0x10) + # int32
  'listDatabases' + raw_string(0x00) + # command
  raw_string(0x01, 0x00, 0x00, 0x00) + # 1
  raw_string(0x00); # end bson document
listDatabases_command = size_encapsulate(data: listDatabases_command);


var query_ismaster = build_query(collection:'admin.$cmd',
                             request_id: 'nes1',
                             bson:ismaster_command);

var query_buildinfo = build_query(collection:'admin.$cmd',
                              request_id: 'nes2',
                              bson:buildinfo_command);

var query_listDatabases = build_query(collection:'admin.$cmd',
                              request_id: 'nes3',
                              bson:listDatabases_command);

# ismaster command should return regardless of authentication
dbg::detailed_log(
  lvl:3,
  src:SCRIPT_NAME,
  msg:'Port ' + port + ': query_ismaster being sent',
  msg_details:{
     "Data":{"lvl":3, "value":query_ismaster}
  });
send(socket:soc, data:query_ismaster);

var response = recv_response(sock:soc);

if (isnull(response))
{
  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:
    'Port ' + port + ': Initial query_ismaster response is NULL');
  close(soc);
  if (max_index(cert_list) > 0)
  {
    var i = -1;
    foreach var cert_array (cert_list)
    {
      i++;
      # Attempt to redo command with an SSL connection
      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:
        'Port ' + port + ': Attempting query_ismaster on SSL using credentials index ' + i);
      soc = open_sock_tcp(port, transport:ENCAPS_IP);
      soc = socket_negotiate_ssl_ex(socket:soc, transport:ENCAPS_SSLv23 | ENCAPS_DISABLE_SSLv2 | ENCAPS_DISABLE_SSLv3,
                                    async:FALSE, ca:cert_array['ca'], cert:cert_array['cert'],
                                    key:cert_array['key'], password:cert_array['key_pass']);
      # ismaster command should return regardless of authentication
      send(socket:soc, data:query_ismaster);

      response = recv_response(sock:soc);
      if (isnull(response))
      {
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:
          'Port ' + port + ': SSL query_ismaster response is NULL using credentials index ' + i);
        close(soc);
        continue;
      }
      ssl_detected = TRUE;
    }
  }
  if (!ssl_detected)
  {
    audit(AUDIT_NOT_LISTEN, 'MongoDB', port);
  }
}

dbg::detailed_log(
  lvl:3,
  src:SCRIPT_NAME,
  msg:'Port ' + port + ': query_ismaster response',
  msg_details:{
     "Data":{"lvl":3, "value":response}
  });

if (
  'nes1' >!< response ||
  'maxBsonObjectSize' >!< response ||
  'ismaster' >!< response
)
{
  close(soc);
  audit(AUDIT_NOT_LISTEN, 'MongoDB', port);
}

var version = 'unknown';

# try to get version, buildinfo command should run without
# auth on almost every version (2.0.0 is a known exception)
send(socket:soc, data:query_buildinfo);

response = recv_response(sock:soc);

dbg::detailed_log(
  lvl:3,
  src:SCRIPT_NAME,
  msg:'Port ' + port + ': query_buildinfo response',
  msg_details:{
     "Data":{"lvl":3, "value":response}
  });

var version_tag = raw_string(0x02, # str identifier
                         0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, # 'version'
                         0x00);

var git_version_tag = raw_string(0x02, # str identifier
                             0x67, 0x69, 0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, # 'gitVersion'
                             0x00);

var ver_str = NULL;
if (!isnull(response) && version_tag >< response)
{
  var ver_offset = stridx(response, version_tag) + strlen(version_tag);
  var ver_str_len = getdword(blob:response, pos:ver_offset);
  if (
    ver_offset+4+ver_str_len-2 <= strlen(response) &&
    ver_str_len > 0 && !isnull(ver_str_len)
  ) ver_str = substr(response, ver_offset+4, ver_offset+4+ver_str_len-2);
}

var git_ver_str = NULL;
if (!isnull(response) && git_version_tag >< response)
{
  var git_ver_offset = stridx(response, git_version_tag) + strlen(git_version_tag);
  var git_ver_str_len = getdword(blob:response, pos:git_ver_offset);
  if (
    git_ver_offset+4+git_ver_str_len-2 <= strlen(response) &&
    git_ver_str_len > 0 || !isnull(git_ver_str_len)
  ) git_ver_str = substr(response, git_ver_offset+4, git_ver_offset+4+git_ver_str_len-2);
}

if (!isnull(ver_str)) version = ver_str;

# Try to get the databases
send(socket:soc, data:query_listDatabases);

response = recv_response(sock:soc);

dbg::detailed_log(
  lvl:3,
  src:SCRIPT_NAME,
  msg:'Port ' + port + ': query_listDatabases response',
  msg_details:{
     "Data":{"lvl":3, "value":response}
  });

var name;
var names = {};
var name_remainder = response;
var name_pos, name_len, val;

while(stridx(name_remainder, 'name') > -1)
{
  name_pos = stridx(name_remainder, 'name') + strlen('name') + 1; # Strings are null terminated, add one more byte for NULL
  name_remainder = substr(name_remainder, name_pos);
  name_len = getdword(blob:name_remainder, pos:0);
  if(name_len > 0 && name_len < strlen(name_remainder))
  {
    name = '';
    for(i = 0; i < name_len; i++)
    {
      val = getbyte(blob:name_remainder, pos:4+i);
      if(val != 0)
        name += raw_string(val);
    }
    names[name] = '';
  }
}

var name_report = '';
var first = TRUE;
var collections, collections_count, listCollections_command, query_listCollections, collection_remainder;
var collection_pos, collection_len, collection_str, collection;

foreach name (keys(names))
{
  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:
    'Port ' + port + ': Processing collections for database ' + name);
  if(!first)
  {
    name_report += '               ';
  }
  first = FALSE;
  name_report += ' '+name+' - ';

  collections = make_list();
  collections_count = 0;

  listCollections_command =
    raw_string(0x10) + # int32
    'listCollections' + raw_string(0x00) + # command
    raw_string(0x01, 0x00, 0x00, 0x00) + # 1
    raw_string(0x00); # end bson document
  listCollections_command = size_encapsulate(data: listCollections_command);

  query_listCollections = build_query(collection:name+'.$cmd',
                                request_id: 'nes4',
                                bson:listCollections_command);

  # Try to get the databases
  send(socket:soc, data:query_listCollections);

  response = recv_response(sock:soc);

  dbg::detailed_log(
    lvl:3,
    src:SCRIPT_NAME,
    msg:'Port ' + port + ': query_listCollections response',
    msg_details:{
       "Data":{"lvl":3, "value":response}
    });

  collections = make_list();
  var collection_count = 0;
  collection_remainder = response;

  while(stridx(collection_remainder, 'name') > -1)
  {
    collection_pos = stridx(collection_remainder, 'name') + strlen('name') + 1; # Strings are null terminated, add one more byte for NULL
    collection_remainder = substr(collection_remainder, collection_pos);
    collection_len = getdword(blob:collection_remainder, pos:0);
    if(collection_len > 0 && collection_len < strlen(collection_remainder))
    {
      collection = '';
      for(i = 0; i < collection_len; i++)
      {
        val = getbyte(blob:collection_remainder, pos:4+i);
        if(val != 0)
          collection += raw_string(val);
      }
      collections[collection_count++] = collection;
    }
  }
  collection_str = '';
  foreach collection (collections)
  {
    collection_str += collection+',';
     
  }
  #trim trailing comma
  if(len(collections) > 0)
    collection_str = substr(collection_str, 0, strlen(collection_str)-2);
  else
    name_report += 'collections could not be enumerated';
  name_report += collection_str+'\n';
  names[name] = collection_str;
  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:
    'Port ' + port + ': Collections for database ' + name + ': ' + serialize(collections));
}



close(soc);
mongodb_detected = TRUE;
register_service(port:port, ipproto:'tcp', proto:MONGODB_PROTO);

var report = '\n  Version     : ' + version;
set_kb_item(name:'mongodb/' + port + '/Version', value: version);

if (ssl_detected)
{
   replace_kb_item(name:'MongoDB/require_ssl/' + port, value:TRUE);
   report += '\n  SSL is required for the MongoDB running on this port.';
}

if (!isnull(git_ver_str))
{
   set_kb_item(name:'mongodb/' + port + '/GitVersion', value: git_ver_str);
   report += '\n  Git version : ' + git_ver_str;
}

# Check for the managed MongoDB instance that uses Cosmos DB API
var managed_service;
if (check_for_cosmosdb_api(port:port))
  managed_service = 'Azure Cosmos DB API';

if (!empty_or_null(managed_service))
{
  extra['Managed Service'] = managed_service;
  extra_no_report['Managed'] = TRUE;

  # Needed for downstream plugins
  set_kb_item(name:strcat('mongodb/', port, '/Managed'), value:TRUE);
  report += '\n  Managed Service : ' + managed_service;
}

if(!empty_or_null(names) && name_report != '')
{
  foreach name (keys(names))
  {
    set_kb_item(name:'mongodb/' + port + '/Databases', value: name);
    if(!empty_or_null(names[name]))
      set_kb_item(name:'mongodb/' + port + '/Collections/' + name, value:names[name]);
  }
  report += '\n  Databases   :' + name_report;
}

report += '\n';

if (version == 'unknown')
{
  report = '\nUnable to obtain version information for MongoDB instance.\n';
}

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

if (!mongodb_detected)
  audit(AUDIT_NOT_INST, 'MongoDB');
else
  replace_kb_item(name:'mongodb', value:TRUE);



register_install(
  vendor   : "MongoDB",
  product  : "MongoDB",
  app_name : app,
  vendor   : 'MongoDB',
  product  : app,
  version  : version,
  port     : port,
  service  : service,
  extra    : extra,
  extra_no_report : extra_no_report,
  cpe      : cpe
);
