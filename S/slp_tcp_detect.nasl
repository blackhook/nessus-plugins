#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(23777);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/27");

  script_name(english:"SLP Server Detection (TCP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote server supports the Service Location Protocol.");
  script_set_attribute(attribute:"description", value:
"The remote server understands Service Location Protocol (SLP), a
protocol that allows network applications to discover the existence,
location, and configuration of various services in an enterprise
network environment.  A server that understands SLP can either be a
service agent (SA), which knows the location of various services, or a
directory agent (DA), which acts as a central repository for service
location information.");
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc2608.txt");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 427);

  exit(0);
}

include("byte_func.inc");
include("slp.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  var port = get_unknown_svc(427);
  # This is a silent_service()
  if (!port) exit(0);
}
else port = 427;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


var soc = open_sock_tcp(port);
if (!soc) exit(0);

var xid = rand() % 0xffff;
var info = "";

# Send a service request.
foreach var svc (slp::SVC_TYPES)
{
  var req = slp::mk_SLPFindSrv_req(xid:xid, svc:svc);

  # nb: Responses are sometimes sent via UDP; eg, NetWare.
  var filter = "udp and " +
    "src host " + get_host_ip() + " and " +
    "src port " + port + " and " +
    "dst port " + get_source_port(soc);

  var res = send_capture(socket:soc, data:req, pcap_filter:filter);
  if (!res) res = recv(socket:soc, length:4096);

  # If ...
  if (
    # the string is long enough and ...
    strlen(res) > 10 && 
    # the SLP version is at least 2 and ...
    getbyte(blob:res, pos:0) >= 2
  )
  {
    # Determine whether it's a DA or an SA based on the type of response.
    var fn = getbyte(blob:res, pos:1);
    if (fn == 8 && "service:directory-agent://" >< res)
    {
      info = "An SLP Directory Agent is listening on this port.";
      break;
    }
    else if (fn == 11 && "service:service-agent://" >< res)
    {
      info = "An SLP Service Agent is listening on this port.";
      break;
    }
    else if (fn == 2)
    {
      info = 'An SLP server is listening on this port, but Nessus was unable\n' +
             'to determine whether it was a Directory or a Service Agent.';
      # don't break -- we'll use this as a fall-back.
    }
  }
}


if (info)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"slp");

  # Send a service type request to try to discover known services.
  #
  # nb: support for this is optional.
  xid += 1;
  req = slp::mk_SLPFindSrvType_req(xid:xid);

  # nb: UA's can send this using TCP.
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);
  if (
    # the string is long enough and ...
    strlen(res) > 20 && 
    # the SLP version is at least 2 and ...
    getbyte(blob:res, pos:0) >= 2 && 
    # it's a Service Type Reply and ...
    getbyte(blob:res, pos:1) == 10
  )
  {
    var svcs = split(substr(res, 20), sep:",", keep:FALSE);
    info += '\n' +
            '\n' +
            'In addition, Nessus was able to learn that the agent knows about\n' +
            'the following services :\n' +
            '\n';
    var count = 0;
    foreach svc (sort(svcs))
    {
      # length sanity check because good practice and because CVE-2023-29552
      if (count >= slp::SLP_ATTR_LIMIT && !thorough_tests)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Not reporting all SLP services since we found '+len(svcs)+' total.');
        break;
      }
      replace_kb_item(name: 'SLP/svc/'+svc, value: 1);
      xid += 1;
      req = slp::mk_SLPFindAttrs_req(xid:xid, svc_url:svc);
      send(socket:soc, data:req);
      res = recv(socket:soc, length:1024);
      if (empty_or_null(object: res)) continue;
      var attr_list_len = getword(blob:res, pos:18);
      if (attr_list_len <= 0 ) continue;
      if (attr_list_len > slp::SLP_ATTR_LIST_LEN_LIMIT && !thorough_tests)
      {
        attr_list_len = slp::SLP_ATTR_LIST_LEN_LIMIT;
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'SLP attribute list length exceeded '+slp::SLP_ATTR_LIST_LEN_LIMIT+', truncating.');
      }
      var attr_list = substr(res, 20, 20 + attr_list_len);
      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'SLP attribute list:'+attr_list);
      
      replace_kb_item(name: 'SLP/svc/'+svc, value: attr_list);
      info += '  ' + svc + '\n';
      count ++;
    }
  }

  security_note(port:port, extra: '\n'+info);
}

close(soc);
