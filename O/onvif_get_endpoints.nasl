include("compat.inc");

if (description)
{
  script_id(103866);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/10/31 18:41:24 $");

  script_name(english:"ONVIF Device Services");
  script_summary(english:"Parses the GetCapabilities response");

  script_set_attribute(attribute:"synopsis", value:
"The remote service responded to an ONVIF GetCapabilities request");
  script_set_attribute(attribute:"description", value:
"Nessus was able to map the enabled ONVIF services on the remote
device by sending a GetCapabilities SOAP request.");
  script_set_attribute(attribute:"see_also", value:"https://www.onvif.org/");
  script_set_attribute(attribute:"solution", value:
"Enable IP filtering if possible. Disable ONVIF if it isn't in use.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencie("onvif_detect.nbin");
  script_require_keys("onvif/present");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('audit.inc');

##
# Sends a GetCapabilities request and parses the response. The SOAP
# envelope should contain all the namespaces that are used. We search
# for anything ending in "wsdl" and try to map the name to a capability.
#
# @param port the port to send the request to
# @param uri the uri to send the request to
#
# @return NULL or the list of mappings.
# @NOTE this function can audit out.
##
function do_get_capabilities(port, uri)
{
  var soap_info =
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' +
      '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">' +
        '<GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl" />' +
      '</s:Body>' +
     '</s:Envelope>';

  var response = http_send_recv3(
    method:"POST",
    port:port,
    item:uri,
    content_type:'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetCapabilities"',
    data:soap_info,
    exit_on_fail:FALSE);

  if ("401" >< response[0] || "NotAuthorized" >< response[2])
  {
    exit(1, "The service listening on port " + port + " requires authentication for " +
      "a GetCapabilitiesResponse request to " + uri);
  }

  if ("200" >!< response[0] || ":GetCapabilitiesResponse>" >!< response[2])
  {
    audit(AUDIT_RESP_BAD, port, "the GetCapabilities request");
  }

  # extract the soap envelope. We can pull the namespaces out of it
  var envelope = pregmatch(string:response[2], pattern:"<SOAP-ENV:Envelope([^>]+)>", icase:TRUE);
  if (empty_or_null(envelope))
  {
    audit(AUDIT_RESP_BAD, port, "the GetCapabilities request");
  }

  # extract every namespace that ends that ends in /wsdl
  var endpoint_report = NULL;
  var namespaces = strstr(response[2], "xmlns:");
  for ( ; namespaces != NULL; namespaces = strstr(namespaces, "xmlns:"))
  {
    # extract the individual endpoint
    var ns = pregmatch(string:namespaces, pattern:'"(http://[^"]+)"', icase:TRUE);
    if (!empty_or_null(ns))
    {
      var wsdl = pregmatch(string:chomp(ns[1]), pattern:".+/([^/]+)/wsdl$");
      if (!empty_or_null(wsdl))
      {
        var xaddr = pregmatch(string:response[2], pattern:":" + wsdl[1] + "><[^:]+:XAddr>(http[^<]+)", icase:1);
        if (!empty_or_null(xaddr))
        {
          var parsed_url = split_url(url:xaddr[1]);
          if (!empty_or_null(parsed_url))
          {
            set_kb_item(name:'onvif/http/' + port + '/endpoint/' + ns[1], value:parsed_url["page"]);

            endpoint_report += '\n';
            endpoint_report += ns[1];
            endpoint_report += " => ";
            endpoint_report += xaddr[1];
          }
        }
      }
      
      # increment and continue
      namespaces = substr(namespaces, len(ns[0]));
    }
    else
    {
      # increment and continue
      namespaces = substr(namespaces, 1);
    }
  }
  return endpoint_report;
}

get_kb_item_or_exit('onvif/present');
port = get_kb_item_or_exit('onvif/http/port');
uri = get_kb_item_or_exit('onvif/http/' + port + '/uri');

endpoint_report = do_get_capabilities(port:port, uri:uri);
if (empty_or_null(endpoint_report))
{
  exit(1, "Nessus didn't find any ONVIF services on port " + port);
}

report = 'The ONVIF server on port ' + port +
  ' supports these services:\n' + endpoint_report + '\n';
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
