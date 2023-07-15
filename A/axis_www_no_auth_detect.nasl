#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122369);
  script_version("1.5");
  script_cvs_date("Date: 2020/01/22");

  script_name(english:"AXIS Camera Unsecured Feed Detection");
  script_summary(english:"Checks for Axis Network Camera Unsecured Feed");

  script_set_attribute(attribute:"synopsis", value:
"The remote device has an unsecured camera feed.");

  script_set_attribute(attribute:"description", value:
"The remote host seems to be an Axis Network Camera. It was possible to
access the camera feed remotely without supplying credentials.");

  # https://www.networkworld.com/article/2318112/lan-wan/public-nannycams.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edddb117");
  script_set_attribute(attribute:"solution", value:
"Follow the vendor recommendation for securing the camera feed.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:axis:network_camera");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("axis_www_detect.nbin");
  script_require_keys("installed_sw/AXIS device");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("spad_log_func.inc");

##
# For debugging, uncomment the following
# set_kb_item(name:'global_settings/enable_plugin_debugging', value:'TRUE');
##

get_install_count(app_name:"AXIS device", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
spad_log(message:'Operating on port ' + port + '\n');

install = get_single_install(app_name:"AXIS device", port:port);
spad_log(message:'get_single_install() returned: ' + obj_rep(install) + '\n');

##
#  If we have gotten this far, we are working with a device
#  which has been identified as an Axis camera.
##

##
#  Public feed path.  Specified in array form so that additional paths 
#  can be easily added in the future.
##
paths = [
  "/view/viewer_index.shtml",
  "/view/index.shtml",
  "/view/view.shtml"
  ];


feed_found = FALSE;
report = "";

foreach path (paths)
{
  ##
  #  Attempt to connect to the unsecured feed
  ##
  res = http_send_recv3(method:'GET', item:path, port:port, exit_on_fail:FALSE);
  spad_log(message:'http_send_recv3() of path ' + path + '\nreturned: ' + obj_rep(res) + '\n');

  ##
  #  Note: requiring string 'www.axis.com' to avoid false positive when
  #   authentication popup is presented.
  ##
  if (empty_or_null(res) || "200 OK" >!< res[0] || res[2] !~ "www.axis.com")
  {
    spad_log(message:'Unsuccessful connection for port ' + port + '.  Continuing.\n');
    continue;
  }

  feed_found = TRUE;
  if (empty_or_null(report))
  {
    report += '\nThe following URL(s) display a live camera feed without requiring authentication:\n' +
           '\n' + build_url(port:port, qs:path) + '\n';
  }
  else
  {
    report += '\n' + build_url(port:port, qs:path) + '\n';
  }
  
}

if (feed_found)
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
else
  audit(AUDIT_NOT_DETECT, "An unsecured live camera feed");


exit(0);

