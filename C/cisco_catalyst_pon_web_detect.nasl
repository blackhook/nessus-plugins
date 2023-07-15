#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155349);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Cisco Catalyst PON Series Web Detection");
  script_set_attribute(attribute:"synopsis", value:
"Checks the login page for a Cisco Catalyst PON Series device.");
  script_set_attribute(attribute:"description", value:
"The web management interface for a Cisco Catalyst PON Series device was
detected on the remote host.");
  # https://www.cisco.com/c/en/us/products/switches/catalyst-pon-series/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfd37941");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:catalyst_pon_switch_cgp-ont");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:catalyst_pon_switch_cgp-ont-1p");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:catalyst_pon_switch_cgp-ont-4p");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:catalyst_pon_switch_cgp-ont-4pv");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:catalyst_pon_switch_cgp-ont-4pvc");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:catalyst_pon_switch_cgp-ont-4tvcw");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");

app_name = "Cisco Catalyst PON WebUI";

port = get_http_port(default:443, embedded:TRUE);

# RES-79302: All 4P series devices share the same firmware image. And, without a
# Cisco Catalyst Pon series device there does not exist reliable method to detect 
# observable differences between the 4P series. The gStatusDevice.asp page 
# will have this information in a non-emulated web-ui through getInfo.
cpe = "x-cpe:/h:cisco:catalyst_pon_switch_cgp-ont";

res = http_send_recv3(
  method          : "GET",
  item            : '/login.html',
  port            : port,
  follow_redirect : 1,
  exit_on_fail    : TRUE
);

# if server response is null exit out with a reason
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# Checked against login.html in firmware images for 1P and 4P devices.
if (
  !(
    "ciscosb-login-box" >< res[2] &&
    "GPON ONT"          >< res[2] &&
    "Username"          >< res[2] &&
    "Password"          >< res[2] &&
    "Cisco Systems"     >< res[2]
  )
) audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

# Not able to obtain reliable version information until a device is procured.
version = UNKNOWN_VER;

set_kb_item(name:"Host/Cisco/CatalystPON/Version", value:version);

register_install(
  vendor:"Cisco",
  product:"Catalyst PON Switch CGP-ONT",
  app_name: app_name,
  path: "/login.html",
  port: port,
  version: version,
  webapp: TRUE,
  cpe: cpe
);

report_installs(app_name:app_name, port:port);
