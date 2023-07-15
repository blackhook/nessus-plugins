#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64702);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/25");

  script_name(english:"EMC Data Protection Advisor Web UI Detection");
  script_summary(english:"Detects EMC DPA Web UI");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is part of an automated analysis and alerting
system for backup and replication infrastructure."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The report web server is the Web UI for EMC Data Protection Advisor, an
automated analysis and alerting system for backup and replication
infrastructure."
  );
  # https://www.emc.com/data-protection/data-protection-advisor.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3822e756");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:data_protection_advisor");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443, 9002);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9002);

appname = "EMC Data Protection Advisor Web UI";
kb_appname = "emc_dpa";

installs = NULL;

res = http_send_recv3(
  method:'GET',
  item:'/home',
  port:port,
  exit_on_fail:TRUE
);

if (
  "<title>Data Protection Advisor</title>" >< res[2] &&
  "EMC Corporation" >< res[2]
)
{
  version = UNKNOWN_VER;

  res = http_send_recv3(
    method:'GET',
    item:'/properties.xml',
    port:port,
    exit_on_fail:TRUE
  );

  item = eregmatch(pattern:'productVersion">([^<]+)', string:res[2]);
  if (!isnull(item)) version = item[1];

  # Register install
  installs = add_install(
    installs:installs,
    ver:version,
    dir:'/',
    appname:kb_appname,
    port:port,
    cpe: "cpe:/a:emc:data_protection_advisor"
  );
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : appname,
    item         : '/'
  );
  security_note(port:port, extra:report);
}
else security_note(port);
