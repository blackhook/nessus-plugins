#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23778);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/27");

  script_name(english:"SLP Server Detection (UDP)");
  script_summary(english:"Detects an SLP server over udp");

  script_set_attribute(attribute:"synopsis", value:
"The remote server supports the Service Location Protocol." );
  script_set_attribute(attribute:"description", value:
"The remote server understands Service Location Protocol (SLP), a
protocol that allows network applications to discover the existence,
location, and configuration of various services in an enterprise
network environment.  A server that understands SLP can either be a
service agent (SA), which knows the location of various services, or a
directory agent (DA), which acts as a central repository for service
location information." );
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc2608.txt" );
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2006-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  exit(0);
}

include("compat_shared.inc");
include('slp.inc');

if ( islocalhost()) exit(0);

var port = 427;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
var soc = open_sock_udp(port);
if (!soc) exit(0);

var info = '';
var xid = rand() % 0xffff;
# Send a service request.
foreach var svc (slp::SVC_TYPES)
{
  var req = slp::mk_SLPFindSrv_req(xid:xid, svc:svc);
  #send(socket:soc, data:req);

  var hostIp = get_host_ip();
  var hostIpNoScope = ereg_replace(string:hostIp, pattern:"(.*)(%.*)", replace:"\1");

  var filter = strcat(
    "udp and ",
    "src host ", hostIpNoScope, " and ",
    "src port ", port, " and ",
    "dst port ", get_source_port(soc)
  );
  var res = send_capture(socket:soc, data:req, pcap_filter:filter);
  if (res == NULL) exit(0);
  res = get_udp_element(udp:res, element:"data");

  # If ...
  if (
    # the string is long enough and ...
    strlen(res) > 10 && 
    # the SLP version is at least 2 and ...
    getbyte(blob:res, pos:0) >= 2 && 
    # the XID in the packet is either what we supplied or 0.
    (getword(blob:res, pos:10) == xid || getword(blob:res, pos:10) == 0)
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
  register_service(port:port, ipproto:"udp", proto:"slp");

  # Send a service type request to try to discover known services.
  #
  # nb: support for this is optional.
  xid += 1;
  req = slp::mk_SLPFindSrvType_req(xid:xid);

  res = send_capture(socket:soc, data:req, pcap_filter:filter);
  if (res == NULL) exit(0);
  res = get_udp_element(udp:res, element:"data");

  if (
    # the string is long enough and ...
    strlen(res) > 20 && 
    # the SLP version is at least 2 and ...
    getbyte(blob:res, pos:0) >= 2 && 
    # it's a Service Type Reply and ...
    getbyte(blob:res, pos:1) == 10 &&
    # the XID in the packet is either what we supplied or 0.
    (getword(blob:res, pos:10) == xid || getword(blob:res, pos:10) == 0)
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
      res = send_capture(socket:soc, data:req, pcap_filter:filter);
      if (res == NULL) continue;
      res = get_udp_element(udp:res, element:"data");
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

  security_note(port:port, proto:'udp', extra:'\n'+info);
}

close(soc);
