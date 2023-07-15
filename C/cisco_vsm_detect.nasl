#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69854);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0566");

  script_name(english:"Cisco Video Surveillance Manager Web Detection");
  script_summary(english:"Looks for the vsmc.html page");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web management interface was detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web management interface for Cisco Video Surveillance Management
Console was detected on the remote host."
  );
  # https://www.cisco.com/c/en/us/products/physical-security/video-surveillance-manager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e42e2ce");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:video_surveillance_manager");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80);
app = 'Cisco Video Surveillance Management Console';

dir = '';

res = http_send_recv3(
  method : "GET",
  item   : dir + "/vsmc.html",
  port   : port,
  exit_on_fail : TRUE
);

if (
  "<title>Video Surveillance Management Console" >!< res[2] &&
  'src="inc/packages.php"' >!< res[2]
) audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Try and grab the VSMS version
version = UNKNOWN_VER;

res2 = http_send_recv3(
  method : "GET",
  item   : dir + "/inc/packages.php",
  port   : port,
  exit_on_fail : TRUE
);

if ("<title>Configuration Overview" >< res2[2])
{
  ver = pregmatch(pattern:"Cisco_VSMS-(.*)", string:res2[2], icase:TRUE);
  if (!isnull(ver)) version = ver[1];
}

register_install(
    app_name : app,
    vendor : 'Cisco',
    product : 'Video Surveillance Manager',
    path     : dir,
    version  : version,
    port     : port,
    webapp   : TRUE,
    cpe   : "cpe:/a:cisco:video_surveillance_manager"
);

report_installs(app_name:app, port:port);
