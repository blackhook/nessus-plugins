#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118039);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Java JMX Agent Insecure Configuration");

  script_set_attribute(attribute:"synopsis", value:
"A remote Java JMX agent is configured without SSL client
and password authentication.");
  script_set_attribute(attribute:"description", value:
"A Java JMX agent running on the remote host is configured
without SSL client and password authentication. An unauthenticated,
remote attacker can connect to the JMX agent and monitor and manage
the Java application that has enabled the agent.

Moreover, this insecure configuration could allow the attacker to
create a javax.management.loading.MLet MBean and use it to create
new MBeans from arbitrary URLs, at least if there is no security
manager. In other words, the attacker could execute arbitrary code
on the remote host under the security context of the remote Java
VM.");
  # https://docs.oracle.com/javadb/10.10.1.2/adminguide/radminjmxenablepwdssl.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d7065e0");
  # https://docs.oracle.com/javase/7/docs/technotes/guides/management/agent.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff9fe54a");
  script_set_attribute(attribute:"solution", value:
"Enable SSL client or password authentication for the JMX agent.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Unauthenticated remote attacker may be able to achieve RCE under the
security context of the remote Java VM.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rmiregistry_detect.nasl");
  script_require_ports("Services/rmi_registry", 1099, 9091);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("rmi.inc");
include("data_protection.inc");

function get_obj_info()
{
  local_var data, len, pos, res, info;
  local_var obj_id, rmi_port, ssl;

  res = _FCT_ANON_ARGS[0];

  rmi_port  = 0;
  obj_id    = NULL;
  ssl       = FALSE;

  info  = NULL;
  if (strlen(res) > 3 &&
      substr(res, 0, 2) == '\x51\xac\xed' &&
      "javax.management.remote.rmi" >< res &&
      "UnicastRef" >< res &&
      strlen((data = strstr(res, "UnicastRef") - "UnicastRef")) > 4
  )
  {
    pos = 0;
    # If UnicastRef2, skip the '2' and TCP endpoint format byte
    if (data[0] == "2")
      pos = 2;

    # Skip the host/IP part of the endpoint
    len = getword(blob:data, pos:pos);
    pos += 2 + len;

    # Make sure there are available bytes for port and ObjectID
    if (len > 0 && pos + 4 + 22 <= strlen(data))
    {
      # Port is an 'int'
      rmi_port = getword(blob:data, pos:pos + 2);
      pos += 4;

      # If com.sun.management.jmxremote.ssl=true,
      # the "SslRMIClientSocketFactory" string shows up in the response
      if("SslRMIClientSocketFactory"  >< data)
      {
        ssl = TRUE;
        data = strstr(data, "SslRMIClientSocketFactory") - "SslRMIClientSocketFactory";
        # Start of TC_BLOCKDATA
        pos = stridx(data,'\x77');
        if(pos != -1 && pos + 2 + 22 <= strlen(data) && ord(data[pos+1]) >=22)
        {
          pos += 2; # Skip TC code and length fields
          obj_id  = substr(data, pos, pos + 22 -1);
        }
      }
      else
      {
        obj_id  = substr(data, pos, pos + 22 -1);
      }
    }
  }

  if(rmi_port && ! isnull(obj_id))
  {
    info.obj_id = obj_id;
    info.rmi_port = rmi_port;
    info.ssl = ssl;
    return info;
  }
  else
    return NULL;
}

function get_utf8(&data, &pos, long)
{
  local_var dlen, n, len, ret;

  if(isnull(long)) long = FALSE;

  dlen = strlen(data);

  n = 2;
  if(long) n = 4;
 
  if(pos + n > dlen) return NULL;

  if(long)
    len = getdword(blob:data, pos: pos);
  else
    len = getword(blob:data, pos: pos);

  pos += n;

  if(len == 0) return NULL;
  if(pos +  len > dlen) return NULL;

  ret = substr(data, pos, pos + len -1);
  pos += len;

  return ret;
}

function get_tc_string(&data, &pos)
{
  local_var dlen, tc;

  dlen = strlen(data);

  if(pos + 1 > dlen) return NULL;
  tc = data[pos++];

  # TC_STRING or TC_LONGSTRING
  if(tc != '\x74' && tc != '\x7c')
    return NULL;

  return get_utf8(data: data, pos: pos);
}

function get_tc_strings(&data, &pos)
{
  local_var arr, count, cn, dlen, i, str, ret;

  dlen = strlen(data);
  if(pos + 2 > dlen) return NULL;

  # Not TC_ARRAY
  if(data[pos++] != '\x75') return NULL;

  # Not TC_CLASSDESC
  if(data[pos++] != '\x72') return NULL;

  # Not String[]
  cn = get_utf8(data:data, pos:pos);
  if(isnull(cn) || cn != '[Ljava.lang.String;')
    return NULL;

  # End of classDesc
  pos = stridx(data, '\x78\x70', pos);

  ret = NULL;
  if(pos != -1 &&  pos + 2 + 4 <= dlen)
  {
    pos += 2;
    # Number of elements
    count = getdword(blob:data, pos: pos);
    pos += 4;
    for(i = 0; i < count; i++)
    {
      str = get_tc_string(data:data, pos:pos);
      if(isnull(str)) return NULL;
      if(str =~ '^-Djavax\\.net\\.ssl\\.(key|trust)StorePassword')
      {
        arr = split(str, sep: '=', keep:TRUE);
        if(max_index(arr) == 2 && strlen(arr[1]) > 1)
        {
          str = arr[0] +  data_protection::sanitize_userpass(text:arr[1]);
        }
      }
      ret[i] = str;
    }
  }
  return ret;
}

function get_obj_attr(socket, rmi_conn, oname, attr)
{
  local_var  blk, data, dlen, len, ret;
  local_var count, i, str;

  if(!soc || strlen(rmi_conn) != 22 ||
    isnull(oname) || isnull(attr)
  ) return NULL;

  data = rmi_conn +
  '\xff\xff\xff\xff' + # operation for RMIv2
  # 8-byte hash identifying the method
  # RMIConnection.getAttribute()
  '\xf0\xe0\x50\x0a\x39\x4d\x72\x15';
  # Call sig
  blk = '\x77' + mkbyte(strlen(data)) + data;
  data = '\x50\xac\xed\x00\x05' + blk +
  # ObjectName
  '\x73\x72\x00\x1b\x6a\x61\x76\x61\x78\x2e\x6d\x61\x6e\x61\x67\x65' +
  '\x6d\x65\x6e\x74\x2e\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x0f' +
  '\x03\xa7\x1b\xeb\x6d\x15\xcf\x03\x00\x00\x70\x78\x70\x74' +
  mkword(strlen(oname)) + oname +
  '\x78' + # TC_BLOCKDATA
  #  String attribute
  '\x74' + mkword(strlen(attr)) + attr +
  # Subject delegationSubject; NULL
  '\x70';
  
  send(socket:soc, data:data);

  data = recv(socket:soc, length:8192);
  dlen = strlen(data);

  if((dlen < 22) ||
    substr(data, 0, 2) != '\x51\xac\xed' ||
    data[5] != '\x77' ||
    ord(data[7]) != 1)  # normal return data
      return NULL;

  i = 22;
  if(oname == 'java.lang:type=Runtime')
  {
    if(attr == 'ClassPath')
    {
      return get_tc_string(data:data,pos:i);
    }
    else if (attr == 'InputArguments')
    {
      ret =  get_tc_strings(data:data,pos:i);
      if(isnull(ret)) return NULL;
      return join(ret, sep: ' ');
    }
    # Other attributes not supported
    else return NULL;
  }
  # Other objects not supported
  else return NULL;
}


#
# Main
#
port = get_service(svc:'rmi_registry', exit_on_fail:TRUE);
soc = rmi_connect(port:port);

# Send client endpoint
myhost= compat::this_host();
clt_endpt = mkword(strlen(myhost)) + myhost + mkdword(0);
send(socket:soc, data: clt_endpt);

#
# Lookup the 'jmxrmi' remote object in the Registry
#
call = raw_string(
0x50, 0xac, 0xed, 0x00, 0x05, 0x77, 0x22, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x02, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6, 0x3b,
0xdf, 0x74, 0x00, 0x06, 0x6a, 0x6d, 0x78, 0x72,
0x6d, 0x69);

send(socket:soc, data: call);
res = recv(socket:soc, length:4096, min:2);
close(soc);

info = get_obj_info(res);
if(isnull(info))
{
  exit(1, 'Failed to get a reference to the remote jmxrmi object.');
}

rmi_port = info.rmi_port;
rmi_serv = info.obj_id;

#
# Make a connection to the RMI port.
#
# If com.sun.management.jmxremote.ssl.need.client.auth=true,
# SSL client authentication is enabled, and rmi_connect()
# will fail as we don't have the correct client certificate.
# 
# This is a secure configuration.
soc = rmi_connect(port:rmi_port, ssl:info.ssl);
send(socket:soc, data: clt_endpt);

#
# Call javax.management.remote.rmi.RMIServer.newClient()
# with NULL credentials
#
data = rmi_serv + 
  '\xff\xff\xff\xff' + # Operation for RMIv2
  # 8-byte hash identifying the method
  '\xf0\xe0\x74\xea\xad\x0c\xae\xa8';

tc_blk = '\x77' + mkbyte(strlen(data)) + data;
call = '\x50\xac\xed\x00\x05' + tc_blk +
        '\x70'; # NULL credentials

send(socket:soc, data: call);
res = recv(socket:soc, length:8192, min:2);
dlen = strlen(res);

if (dlen < 22 &&
    substr(res, 0 , 2) != '\x51\xac\xed'
)
{
  close(soc);
  exit(1, 'Invalid RMI return data.');
}


chk = 'javax.management.remote.rmi.RMIConnectionImpl_Stub';
chk = '\x73\x72' + mkword(strlen(chk)) + chk;
#
# Login OK: vulnerable
if(chk >< res )
{
  #
  # A full RCE exploit check further requires:
  #
  # 1) Creating a javax.management.loading.MLet MBean on the JMX agent.
  #
  # 2) Use the MLet MBean to load an attacker-controlled MBean onto
  #    the JMX agent.
  #
  # 3) Execute code in the attacker-controlled MBean.
  #
  #
  # The target would need to be able to connect to an HTTP server
  # on the Nessus scanner serving the malicious MBean. Some
  # customers' scanning environments may prevent the target from
  # doing so (i.e., firewall rules).
  # 
  # Creating 2 MBeans on the remote JMX agent may render the plugin
  # ACT_DESTRUCTIVE_ATTACK.
  # 
  replace_kb_item(name:'java/jmxremote/noauth', value:TRUE);
  set_kb_item(name:'java/jmxremote/' + port + '/noauth', value:TRUE);

  #
  # Get and save ClassPath and InputArguments.
  # These runtime attributes may be used to identify
  # the Java application running the JMX agent.
  #
  extra = NULL;
  info = get_obj_info(res);
  if(! isnull(info))
  {
    rmi_conn = info.obj_id;
    oname = 'java.lang:type=Runtime';
    foreach attr (['ClassPath', 'InputArguments'])
    {
      ret = get_obj_attr(socket:soc, rmi_conn:rmi_conn, oname:oname, attr:attr);
      if(!isnull(ret))
      {
        set_kb_item(name:'java/jmxremote/' + port + '/' + attr, value:ret);
        extra += '\n' + attr + ': \n' + ret + '\n';
      }
    }
  }
  close(soc);

  security_report_v4(port: port, severity: SECURITY_HOLE, extra:extra);
}
else if ('java.lang.SecurityException' >< res)
{
  close(soc);
  exit(0, 'The remote JMX service at port ' + port + ' appears to have password authentication enabled.');
}
# Unexpected
else
{
  close(soc);
  audit(AUDIT_RESP_BAD, rmi_port);
}
