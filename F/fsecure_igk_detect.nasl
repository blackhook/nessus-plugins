#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52024);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/14");

  script_name(english:"F-Secure Internet Gatekeeper Web Console Detection");
  script_summary(english:"Looks for F-Secure Internet Gatekeeper's login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application for filtering email and
web traffic."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is the Web Console component of F-Secure
Internet Gatekeeper, an enterprise-class email and web filtering
gateway used to identify malware in incoming and outgoing SMTP, HTTP,
FTP and POP3 traffic."
  );
  # https://www.f-secure.com/en/web/business_global/products-for-linux/overview
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f5949c1");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f-secure:internet_gatekeeper");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9012);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:9012, embedded:FALSE);


url = '/login.jsf';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  'title>F-Secure Internet Gatekeeper' >< res[2] ||
  (
    'product-support/internet-gatekeeper' >< res[2] &&
    'function oamSetHiddenInput' >< res[2]
  )
)
{
  # nb: there doesn't seem to be a way to get the version remotely
  #     without credentials.
  version = NULL;

  installs = add_install(
    appname  : "fsecure_igk",
    installs : installs,
    port     : port,
    dir      : "",
    ver      : version,
    cpe      : "cpe:/a:f-secure:internet_gatekeeper"
  );
}
if (isnull(installs))
  exit(0, "F-Secure Internet Gatekeeper was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : url,
    display_name : "F-Secure Internet Gatekeeper"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
