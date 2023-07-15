#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62941);
  script_version("1.7");
  script_cvs_date("Date: 2020/01/22");

  script_name(english:"CoSoSys Endpoint Protector Detection");
  script_summary(english:"Looks for evidence of CoSoSys Endpoint Protector");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server hosts a data loss prevention web application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts CoSoSys Endpoint Protector, a web-based
data loss prevention application."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.endpointprotector.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cososys:endpoint_protector_appliace");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

url = "/";
installs = NULL;
version = NULL;

res = http_get_cache(port:port,item:url, exit_on_fail:TRUE);
if ("<title>Endpoint Protector - Reporting and Administration Tool</title>" >< res)
{
  ver_pat = "/> Version ([0-9.]+) - <b>Appliance</b>";

  item = eregmatch(pattern:ver_pat, string:res);
  if (!isnull(item)) version = item[1];

  # Save info about the install.
  installs = add_install(
    appname  : "cososys_endpoint_protector",
    installs : installs,
    port     : port,
    dir      : "",
    ver      : version,
    cpe      : "cpe:/h:cososys:endpoint_protector_appliace"
  );

}

if (isnull(installs))
  audit(AUDIT_WEB_APP_NOT_INST, "CoSoSys Endpoint Protector", port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : url,
    display_name : "CoSoSys Endpoint Protector"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
