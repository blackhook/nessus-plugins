#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83772);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Cisco TelePresence Server Detection");
  script_summary(english:"Checks for the presence of a Cisco TelePresence Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a management server for teleconferencing
devices.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Cisco TelePresence Server, which is a
management engine for other Cisco TelePresence equipment.");
  # https://www.cisco.com/c/en/us/products/conferencing/telepresence-server/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec71020b");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_7010");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_mse_8710");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_multiparty_media_310");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_multiparty_media_320");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_virtual_machine");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = 'Cisco TelePresence Server';
kb_base = "Cisco/TelePresence_Server";
port = get_http_port(default:80);
url = "/system.xml";

res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);

model_match = pregmatch(
  pattern:"<model>Telepresence Server ([^<]*)</model>",
  string:res[2],
  icase:TRUE
);

if (isnull(model_match)) audit(AUDIT_HOST_NOT, "a " + app);

ver_match = pregmatch(
  pattern:"<softwareVersion>([0-9.\)\(]+)</softwareVersion>",
  string:res[2]
);

model = UNKNOWN_VER;
version = UNKNOWN_VER;
if (!isnull(model_match) && !isnull(model_match[1])) model = model_match[1];
if (!isnull(ver_match) && !isnull(ver_match[1])) version = ver_match[1];

# Hacky correction for Virtual Machine model formatting
if (model == "on Virtual Machine") model = "Virtual Machine";

set_kb_item(name:kb_base + '/Version', value:version);
set_kb_item(name:kb_base + '/Model', value:model);

register_install(
  vendor:"Cisco",
  product:"TelePresence Server Software",
  app_name:app,
  path:url,
  version:version,
  port:port,
  cpe:"cpe:/a:cisco:telepresence_server_software",
  webapp:TRUE
);

if (report_verbosity > 0)
{
  report = '\n  Model            : ' + model +
           '\n  Software version : ' + version +
           '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
