#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(108807);
  script_version ("1.2");
  script_cvs_date("Date: 2019/03/04 12:27:19");

  script_name(english: "Web Form Sending Credentials Using GET (PCI-DSS check)");
  script_summary(english: "Finds web forms that send credentials using HTTP GET.");

  script_set_attribute(attribute:"synopsis", value:
"Web application form sends credentials using HTTP GET request.");
  script_set_attribute(attribute:"description", value:
"The remote web application has a form that sends credentials using
an HTTP GET request. This can cause sensitive information such as
usernames and passwords to be logged by the server in access logs.

Authors of services which use the HTTP protocol SHOULD NOT use GET
based forms for the submission of sensitive data, because this will
cause this data to be encoded in the Request-URI. Many existing
servers, proxies, and user agents will log the request URI in some
place where it might be visible to third parties.

This plugin only runs when 'Check for PCI-DSS compliance' is enabled
in the scan policy.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/533.html");
  script_set_attribute(attribute:"see_also", value:"https://www.w3.org/Protocols/rfc2616/rfc2616-sec15.html#sec15.1.3");
  script_set_attribute(attribute:"solution", value:
"Change web application forms to use HTTP POST instead.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of effect of the configuration error.");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("webmirror.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

port = get_http_port(default:80);

cgi = get_kb_item("www/" + port + "/cgi");

res = http_send_recv3(method:'GET', item:cgi, port:port, exit_on_fail:TRUE);
html = res[2];

if ("<form" >< html)
{
  form_start = stridx(html, "<form");
  form_end = stridx(html, "/form>", form_start);
  if (form_end == -1)
    form_end = strlen(html);
  else
    form_end = form_end + 6;
  form = substr(html, form_start, form_end);
  form = tolower(form);

  if (form =~ 'method[ ]*=[ ]*[\'"]get')
  {
    if (form =~ 'type[ ]*=[ ]*[\'"]password')
    {
      report = 'The following page has a form that sends credentials using a GET request:\n' +
                build_url(port:port, qs:cgi) + '\n\n' +
                'Vulnerable form:\n' +
                crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
                form + '\n' +
                crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
      exit(0);
    }
  }
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, "cgi", cgi);
