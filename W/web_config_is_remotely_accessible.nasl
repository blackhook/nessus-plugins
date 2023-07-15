#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121479);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_name(english:"web.config File Information Disclosure");
  script_summary(english:"Attempts to retrieve web.config.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by an
information disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in the remote web
server due to the disclosure of the web.config file. An
unauthenticated, remote attacker can exploit this, via a simple GET
request, to disclose potentially sensitive configuration information.");
  script_set_attribute(attribute:"solution", value:
"Ensure proper restrictions are in place, or remove the web.config
file if the file is not required.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"information disclosure");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

info = '';
res = http_send_recv3(port:port, method: "GET", item:'/web.config', exit_on_fail:TRUE);

if (!isnull(res) &&
  '<configuration>' >< res[2] &&
  '<system.webServer>' >< res[2]
)
{
  last_request = http_last_sent_request();
  security_report_v4(
    port: port,
    severity: SECURITY_WARNING,
    generic: TRUE,
    line_limit: 5,
    request: make_list(last_request),
    output: chomp(res[2])
  );
}
else
  audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
