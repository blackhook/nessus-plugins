#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72427);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"Web Site Client Access Policy File Detection");
  script_summary(english:"Checks for the file clientaccesspolicy.xml");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a 'clientaccesspolicy.xml' file.");
 script_set_attribute(attribute:"description", value:
"The remote web server contains a client access policy file.  This is a
simple XML file used by Microsoft Silverlight to allow access to
services that reside outside the exact web domain from which a
Silverlight control originated.");
 # https://docs.microsoft.com/en-us/previous-versions/windows/silverlight/dotnet-windows-silverlight/cc197955(v=vs.95)
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4eeeaa2");
 script_set_attribute(attribute:"solution", value:
"Review the contents of the policy file carefully.  Improper policies,
especially an unrestricted one with just '*', could allow for cross-
site request forgery or other attacks against the web server.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# According to Microsoft, Silverlight 4 supports two different
# mechanisms for services to opt-in to cross-domain access:
#
# 1. Place a clientaccesspolicy.xml file at the root of the domain
#    where the service is hosted to configure the service to allow
#    cross-domain access.
#
# 2. Place a valid crossdomain.xml file at the root of the domain
#    where the service is hosted. The file must mark the entire domain
#    public. Silverlight supports a subset of the crossdomain.xml
#    schema.
#
# Since crossdomain.nasl already covers the latter, we only need to
# concern ourselves with the former.

url = "/clientaccesspolicy.xml";

res = http_send_recv3(
  method       : "GET",
  item         : url,
  port         : port,
  exit_on_fail : TRUE
);

if (isnull(res[2]) || "<access-policy>" >!< tolower(res[2])) audit(AUDIT_WEB_FILES_NOT, "clientaccesspolicy.xml", port);

report = NULL;
attach_file = NULL;
output = NULL;
req = chomp(http_last_sent_request());
request = NULL;

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to obtain a client access policy file from the' +
    '\n' + 'remote host at the following URL :' +
    '\n' +
    '\n  ' + req +
    '\n';

  if (report_verbosity > 1)
  {
    output = res[2];
    attach_file = "clientaccesspolicy.xml";
    request = make_list(req);

  }
}
security_report_v4(port:port,
                   extra:report,
                   severity:SECURITY_NOTE,
                   request:request,
                   file:attach_file,
                   output:output,
                   attach_type:'application/xml');
