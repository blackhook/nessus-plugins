#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(20301);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"VMware ESX/GSX Server detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running VMware Server, ESX Server, or
GSX Server.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be running a
VMware server authentication daemon, which likely indicates the remote
host is running VMware Server, ESX Server, or GSX Server.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vmware_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:esx_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:gsx_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/three_digits", 902, "Services/vmware_auth");

  exit(0);
}

#the code
include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

register = 0;
port = get_kb_item("Services/vmware_auth");
if ( ! port )
{
 register++;
 if (thorough_tests) {
  port = get_3digits_svc(902);
  if ( ! port ) exit(0);
 }
 else port = 902;
}
if (!get_tcp_port_state(port)) exit(0);


banner = get_unknown_banner(port: port, dontfetch:0);
if (banner) {
  #220 VMware Authentication Daemon Version 1.00
  #220 VMware Authentication Daemon Version 1.10: SSL Required
  #220 VMware Authentication Daemon Version 1.10: SSL Required, MKSDisplayProtocol:VNC 
  if ("VMware Authentication Daemon Version" >< banner) {
    if ( register ) register_service(port:port, ipproto:"tcp", proto:"vmware_auth");

    security_note(port);

    app = "VMware ESX/GSX Server";
    version = UNKNOWN_VER;
    service = "vmware_auth";
    cpe = "cpe:/a:vmware:vmware_server";

    register_install(
      app_name : app,
      vendor : 'VMWare',
      product : 'GSX Server',
      version  : version,
      port     : port,
      service  : service,
      cpe      : cpe
    );
  }
}
