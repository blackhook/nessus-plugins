include("compat.inc");

if (description)
{
  script_id(104275);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/10/31 18:41:24 $");

  script_name(english:"ONVIF Stream URI");
  script_summary(english:"Acquires the video stream URI from an ONVIF enabled camera");

  script_set_attribute(attribute:"synopsis", value:
"The remote service allows unauthenticated users to retrieve the video stream URI");
  script_set_attribute(attribute:"description", value:
"Nessus was able to retrieve the remote devices video stream URI(s)
by sending GetProfiles and GetStreamUri ONVIF requests.");
  script_set_attribute(attribute:"see_also", value:"https://www.onvif.org/");
  script_set_attribute(attribute:"solution", value:
"Enable authentication or IP filtering if possible. Disable ONVIF if it isn't in use.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencie("onvif_get_endpoints.nasl");
  script_require_keys("onvif/present");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('audit.inc');

# This script first grabs a profile token that we need
# in order to make the GetStreamUri request. We'll then
# loop over all protocol types defined by the ONVIF
# specification so we can get all of the end points.
get_kb_item_or_exit('onvif/present');
port = get_kb_item_or_exit('onvif/http/port');
uri = get_kb_item_or_exit('onvif/http/' + port + '/endpoint/http://www.onvif.org/ver10/media/wsdl');

soap_info =
'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' +
  '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">' +
    '<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>' +
  '</s:Body>' +
 '</s:Envelope>';

response = http_send_recv3(
  method:"POST",
  port:port,
  item:uri,
  content_type:'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/media/wsdl/GetProfiles"',
  data:soap_info,
  exit_on_fail:TRUE);

if ("401" >< response[0] || "NotAuthorized" >< response[2])
{
  exit(1, "The service listening on port " + port + " requires authentication for " +
    "a GetProfiles request to " + uri);
}
if ("200" >!< response[0] || ":GetProfilesResponse>" >!< response[2])
{
  audit(AUDIT_RESP_BAD, port, "the GetProfiles request");
}

# grab the first token and run with it. Example:
# <trt:Profiles fixed="true" token="MainProfileToken">
profiles_tag = pregmatch(string:response[2], pattern:":Profiles ([^>]+)>");
if (empty_or_null(profiles_tag))
{
  exit(1, "Couldn't find the profile tag in the GetProfilesResponse from port " + port);
}

token = pregmatch(string:profiles_tag[1], pattern:'token="([^"]+)"');
if (empty_or_null(token))
{
  exit(1, "Couldn't find the profile token in the GetProfilesResponse from port " + port);
}

# different transports result in different URIs (or not). Try them all.
uris = make_list();
protocols = make_list("UDP", "TCP", "RTSP", "HTTP");
foreach protocol(protocols)
{
  soap_info =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' +
    '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">' +
      '<GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl">' +
        '<StreamSetup>' +
          '<Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>' +
          '<Transport xmlns="http://www.onvif.org/ver10/schema">' +
            '<Protocol>' + protocol + '</Protocol>' +
          '</Transport>' + 
        '</StreamSetup>' +
        '<ProfileToken>' + token[1] + '</ProfileToken>' +
      '</GetStreamUri>' +
    '</s:Body>' +
   '</s:Envelope>';

  response = http_send_recv3(
    method:"POST",
    port:port,
    item:uri,
    content_type:'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/media/wsdl/GetStreamUri"',
    data:soap_info,
    exit_on_fail:TRUE);

  if ("401" >< response[0] || "NotAuthorized" >< response[2])
  {
    # I think its safe to exit here. We are almost certainly going to get unauth for everything
    # and not just one protocol
    exit(1, "The service listening on port " + port + " requires authentication for " +
      "a GetStreamUri request to " + uri);
  }
  if ("200" >!< response[0] || ":GetStreamUriResponse>" >!< response[2])
  {
    continue;
  }

  stream_uri = pregmatch(string:response[2], pattern:":Uri>([^< ]+)?</[^:]+:Uri>");
  if (!empty_or_null(stream_uri))
  {
    uris = make_list(stream_uri[1], uris);
  }
}

if (empty_or_null(uris))
{
  exit(1, "The ONVIF server on " + port + " did not provide a stream URI");
}

# some of the protocols will just report the same URI
uris = list_uniq(uris);

report = 'The ONVIF server on port ' + port + ' advertises' +
  '\na video stream at the following URI(s):' + '\n';
foreach uri(uris)
{
  report += '\n';
  report += uri;

  set_kb_item(name:'onvif/stream/' + port, value:uri);
}
report += '\n';
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
