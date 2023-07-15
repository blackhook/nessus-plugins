include("compat.inc");

if (description)
{
  script_id(103868);
  script_version("1.3");
  script_cvs_date("Date: 2018/05/16 19:05:10");

  script_name(english:"ONVIF Get Device User List");
  script_summary(english:"Requests the ONVIF user list");

  script_set_attribute(attribute:"synopsis", value:
"The remote service responded to an ONVIF GetUsers request");
  script_set_attribute(attribute:"description", value:
"Nessus was able to extract a user list from the ONVIF-enabled
device by sending a GetUsers SOAP request to the device");
  script_set_attribute(attribute:"see_also", value:"https://www.onvif.org/");
  script_set_attribute(attribute:"solution", value:
"Enable authentication or IP filtering if possible. Disable ONVIF if it isn't in use.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencie("onvif_get_endpoints.nasl");
  script_require_keys("onvif/present");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('audit.inc');
include("data_protection.inc");

get_kb_item_or_exit('onvif/present');
port = get_kb_item_or_exit('onvif/http/port');
uri = get_kb_item_or_exit('onvif/http/' + port + '/endpoint/http://www.onvif.org/ver10/device/wsdl');

soap_info =
'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' +
  '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">' +
    '<GetUsers xmlns="http://www.onvif.org/ver10/device/wsdl"/>' +
  '</s:Body>' +
 '</s:Envelope>';

response = http_send_recv3(
  method:"POST",
  port:port,
  item:uri,
  content_type:'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetUsers"',
  data:soap_info,
  exit_on_fail:TRUE);

if ("401" >< response[0] || "NotAuthorized" >< response[2])
{
  exit(1, "The service listening on port " + port + " requires authentication for " +
    "a GetUsers request to " + uri);
}
if ("200" >!< response[0] || ":GetUsersResponse>" >!< response[2])
{
  audit(AUDIT_RESP_BAD, port, "the GetUsers request");
}

users_report = NULL;
for (all_users = strstr(response[2], ":Username>");
     all_users != NULL;
     all_users = strstr(all_users, ":Username>"))
{
  user = pregmatch(string:all_users, pattern:":Username>([^<]+)</[^:]+:Username>");
  if (!empty_or_null(user))
  {
    user[1] = data_protection::sanitize_user_enum(users:user[1]);
    users_report += '\n';
    users_report += user[1];

    # increment and continue
    all_users = substr(all_users, len(user[0]));
  }
  else
  {
    # we've failed. terminate the loop
    all_users = NULL;
  }
}

if (empty_or_null(users_report))
{
  exit(1, "Nessus failed to find any users for the service on port " + port);
}

report = 'Nessus found the following valid usernames for ' +
'the ONVIF server on port ' + port + ':\n' + users_report + '\n';
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
