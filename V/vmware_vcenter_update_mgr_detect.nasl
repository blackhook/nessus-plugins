#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56957);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/22");

  script_name(english:"VMware vCenter Update Manager Detection");
  script_summary(english:"Check for health.xml");

  script_set_attribute(attribute:"synopsis", value:"A patch management application was detected on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"VMware vCenter Update Manager (also known as vSphere Update Manager)
was detected on the remote host.  This application is used to manage
patches on vSphere hosts."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/products.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_update_manager");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/www", 9084);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/jetty");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9084);
banner = get_http_banner(port:port, exit_on_fail:TRUE);

if ('Jetty' >!< banner)
  exit(0, 'The web server on port ' + port + ' doesn\'t appear to be Jetty (used by VUM).');

dir = '';
url = dir + '/vci/downloads/health.xml';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if ('<name>VMware Update Manager</name>' >!< res[2])
  exit(0, 'VMware vCenter Update Manager doesn\'t appear to be on port ' + port + '.');

install = add_install(appname:'vcenter_update_mgr', port:port, dir:dir, cpe: "cpe:/a:vmware:vcenter_update_manager");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'VMware vCenter Update Manager',
    installs:install,
    port:port,
    item:url
  );
  security_note(port:port, extra:report);
}
else security_note(port);

