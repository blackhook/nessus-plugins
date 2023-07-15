include("compat.inc");

if (description)
{
  script_id(103867);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/11/15 18:01:11 $");

  script_name(english:"ONVIF Camera Snapshot");
  script_summary(english:"Acquires a snapshot from an ONVIF enabled camera");

  script_set_attribute(attribute:"synopsis", value:
"The remote service allows unauthenticated users to view camera snapshots");
  script_set_attribute(attribute:"description", value:
"Nessus was able to acquire a snapshot from the remote camera using
the GetProfiles and GetSnapshotUri ONVIF requests.");
  script_set_attribute(attribute:"see_also", value:"https://www.onvif.org/");
  script_set_attribute(attribute:"solution", value:
"Enable authentication or IP filtering if possible. Disable ONVIF if it isn't in use.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

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
# in order to make the GetSnapshotUri request. If we are able
# to successfully get a response to GetSnapshotUri then we'll
# attempt to download a snaphsot and attach it to a security
# report
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
if ("200" >!< response[0] || ":GetProfilesResponse>" >!< response[2]) audit(AUDIT_RESP_BAD, port, "the GetProfiles request");

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

soap_info =
'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' +
  '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">' +
    '<GetSnapshotUri xmlns="http://www.onvif.org/ver10/media/wsdl">' +
    '<ProfileToken>' + token[1] + '</ProfileToken>' +
    '</GetSnapshotUri>' +
  '</s:Body>' +
 '</s:Envelope>';

response = http_send_recv3(
  method:"POST",
  port:port,
  item:uri,
  content_type:'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri"',
  data:soap_info,
  exit_on_fail:TRUE);

if ("401" >< response[0] || "NotAuthorized" >< response[2])
{
  exit(1, "The service listening on port " + port + " requires authentication for " +
    "a GetSnapshotUri request to " + uri);
}
if ("200" >!< response[0] || ":GetSnapshotUriResponse>" >!< response[2]) audit(AUDIT_RESP_BAD, port, "the GetSnapshotUri request");

snapshot_uri = pregmatch(string:response[2], pattern:":Uri>([^< ]+)?</[^:]+:Uri>");
if (empty_or_null(snapshot_uri))
{
  exit(1, "Couldn't find the snapshot URI in the GetSnaphsotUriResponse from port " + port);
}

parsed_url = split_url(url:snapshot_uri[1]);
if (empty_or_null(parsed_url))
{
  exit(1, "The GetSnapshotUriResponse from port " + port + " doesn't appear to be a URL");
}

response = http_send_recv3(
  method:"GET",
  port:parsed_url["port"],
  item:parsed_url["page"],
  exit_on_fail:TRUE);

if ("200" >!< response[0] || empty_or_null(response[2]))
{
  exit(1, "Failed to retrieve the snapshot from " + snapshot_uri[1]);
}

# look for the jpeg header
type = NULL;
name = NULL;
if (response[2][0] == '\xff' && response[2][1] == '\xd8' &&
    response[2][2] == '\xff' &&
    (response[2][3] == '\xdb' || response[2][3] == '\xe0' || response[2][3] == '\xe1'))
{
  type = "image/jpeg";
  name = "camera_snapshot.jpeg";
}
else
{
  exit(1, "Didn't recognize the image format from " + parsed_url["page"] + " on port " + parsed_url["port"]);
}

set_kb_item(name:'onvif/snapshot/' + port, value:snapshot_uri[1]);
report = 
  '\n' + "It was possible to obtain a screenshot from the following URL" +
  '\n' + "on the remote camera: " +
  '\n' +
  '\n' + snapshot_uri[1] +
  '\n';

attachments = make_list();
attachments[0] = make_array();
attachments[0]["type"] = type;
attachments[0]["name"] = name;
attachments[0]["value"] = response[2];
security_report_with_attachments(level:0, port:port, extra:report, attachments:attachments);
