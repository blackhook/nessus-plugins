include("compat.inc");

if (description)
{
  script_id(103865);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/10/17 15:56:40 $");

  script_name(english:"ONVIF Device Information");
  script_summary(english:"Parses the DeviceInformation response");

  script_set_attribute(attribute:"synopsis", value:
"The remote service responded to an ONVIF GetDeviceInformation request");
  script_set_attribute(attribute:"description", value:
"Nessus was able to extract some information about the ONVIF-enabled
device by sending a GetDeviceInformation SOAP request to the device
server.");
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

get_kb_item_or_exit('onvif/present');
port = get_kb_item_or_exit('onvif/http/port');
uri = get_kb_item_or_exit('onvif/http/' + port + '/endpoint/http://www.onvif.org/ver10/device/wsdl');

soap_info =
'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' +
  '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">' +
    '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>' +
  '</s:Body>' +
 '</s:Envelope>';

response = http_send_recv3(
  method:"POST",
  port:port,
  item:uri,
  content_type:'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"',
  data:soap_info,
  exit_on_fail:TRUE);

if ("401" >< response[0] || "NotAuthorized" >< response[2])
{
  exit(1, "The service listening on port " + port + " requires authentication for " +
  	"a GetDeviceInformation request to " + uri);
}
if ("200" >!< response[0] || ":GetDeviceInformationResponse>" >!< response[2]) audit(AUDIT_RESP_BAD, port, "the GetDeviceInformation request");

# example (see ONVIF Core Spec v.210 page 68):
# <tds:FirmwareVersion>V11.6.5.1.1-20161213</tds:FirmwareVersion>
# <tds:SerialNumber>00E0F8A206D4</tds:SerialNumber>
# <tds:HardwareId>V11.6.5.1.1-20161213</tds:HardwareId>
firmware_version = pregmatch(string:response[2], pattern:":FirmwareVersion>([^>]+)</[^:]+:FirmwareVersion");
model = pregmatch(string:response[2], pattern:":Model>([^>]+)</[^:]+:Model");
manufacturer = pregmatch(string:response[2], pattern:":Manufacturer>([^>]+)</[^:]+:Manufacturer");

if (empty_or_null(firmware_version) &&
    empty_or_null(model) &&
    empty_or_null(manufacturer))
{
  # we got nothing? fail
  audit(AUDIT_RESP_BAD, port);
}

var report = '\nThe ONVIF service listening on ' + port + ' replied to' +
  '\nthe GetDeviceInformation request with the following information:\n';

if (!empty_or_null(firmware_version))
{
  report += '\nFirmware Version: ' + firmware_version[1];
  set_kb_item(name:'onvif/http/' + port + '/fw_version', value:firmware_version[1]);
}

if (!empty_or_null(model))
{
  report += '\nModel: ' + model[1];
}

if (!empty_or_null(manufacturer))
{
  report += '\nManufacturer: ' + manufacturer[1];
}
report += '\n';

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
