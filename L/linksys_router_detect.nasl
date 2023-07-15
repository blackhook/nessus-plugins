#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44391);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Linksys Router Detection");
  script_summary(english:"Detects Linksys Routers");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is a Linksys router.");
  script_set_attribute(attribute:"description", value:
"The remote device is a Linksys router.  These devices route packets
and may provide port forwarding, DMZ configuration and other
networking services.");
  script_set_attribute(attribute:"see_also", value:"https://www.linksys.com/us/");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this device agrees with your organization's
acceptable use and security policies." );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date",value:"2010/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:linksys_wrt54gc_router");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'Linksys';
port = get_http_port(default:80, embedded:TRUE);

# it would be nice to do a banner check here before possibly making
# a request to HNAP, but there are so many different banner versions
# Sometimes "Linksys" appaers in the banner. Sometimes just the
# model name. Sometimes neither. Really a mess.

res = http_get_cache(item:"/HNAP1/", port:port, exit_on_fail:TRUE);

if ("<VendorName>Linksys by Cisco</VendorName>" >!< res &&
    "<VendorName>Linksys</VendorName>" >!< res)
{
  audit(AUDIT_HOST_NOT, "a Linksys router");
}

version = NULL;
extra_array = make_array();
match = pregmatch(string:res, pattern:'<FirmwareVersion>([^<]+)</FirmwareVersion>');
if (!empty_or_null(match))
{
  version = match[1];
}

match = pregmatch(string:res, pattern:'<ModelName>([^<]+)</ModelName>');
if (!empty_or_null(match))
{
  extra_array["model"] = match[1];
}

match = pregmatch(string:res, pattern:'<ModelDescription>([^<]+)</ModelDescription>');
if (!empty_or_null(match))
{
  extra_array["model_description"] = match[1];
}

match = pregmatch(string:res, pattern:'<DeviceName>([^<]+)</DeviceName>');
if (!empty_or_null(match))
{
  extra_array["device_name"] = match[1];
}

match = pregmatch(string:res, pattern:'<Type>([^<]+)</Type>');
if (!empty_or_null(match))
{
  extra_array["type"] = match[1];
}

replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
register_install(
    vendor:"Cisco",
    product:"Linksys Wrt54gc Router Firmware",
    app_name:appname,
    path:'/',
    version:version,
    extra:extra_array,
    port:port,
    webapp:TRUE,
    cpe: "cpe:/a:cisco:linksys_wrt54gc_router_firmware");

report_installs(app_name:appname, port:port);
