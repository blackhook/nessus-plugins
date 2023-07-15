#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69075);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/05");

  script_xref(name:"IAVT", value:"0001-T-0549");

  script_name(english:"Cisco Email Security Appliance Version");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version of the remote appliance.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Cisco Email Security Appliance (ESA), an
email gateway security appliance.

It was possible to get the ESA version number via SSH or HTTP.");
  # https://www.cisco.com/c/en/us/products/security/email-security/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a744d445");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "cisco_esa_web_detect.nasl");
  script_require_ports("Host/AsyncOS/Cisco Email Security Appliance", "www/cisco_esa");

  exit(0);
}

include("webapp_func.inc");

##
# Saves the provided ESA version number in the KB, generates plugin output,
# and exits.  If a model is provided it is also saved in the KB and reported,
# but a model is not required.
#
# @param ver    ESA version number
# @param model  ESA model
# @param source service used to obtain the version
# @param port   Port used in detection
# @param proto  Protocol used in detection (udp or tcp) (defaults to tcp)

# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, model, source, port, proto)
{
  local_var report, display_ver, host, report_items, ordered_fields;

  if(isnull(proto)) proto = 'tcp';

  # versions look like w.x.y-z (includes a dash)
  # in order to allow them to be used easily with existing functions (namely ver_compare()),
  # they will also be converted to and saved in the kb as w.x.y.z (no dash)
  display_ver = ver;
  ver = str_replace(string:ver, find:'-', replace:'.');

  report_items = { 'Source' : source, 'Version' : ver };
  ordered_fields = [ 'Source', 'Version' ];

  set_kb_item(name:"Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", value:display_ver);
  set_kb_item(name:"Host/AsyncOS/Cisco Email Security Appliance/Version", value:ver);
  set_kb_item(name:"Host/AsyncOS/Cisco Email Security Appliance/Port", value:port);
  set_kb_item(name:"Host/AsyncOS/Cisco Email Security Appliance/Protocol", value:proto);

  host = "AsyncOS " + display_ver + " on Cisco Email Security Appliance";
  if (!isnull(model))
  {
    host = host + " " + model;
    set_kb_item(name:"Host/AsyncOS/Cisco Email Security Appliance/Model", value:model);

    report_items['Model'] = model;
    append_element(var:ordered_fields, value:'Model');
  }

  set_kb_item(name:"Host/OS/AsyncOS", value:host);
  set_kb_item(name:"Host/OS/AsyncOS/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/AsyncOS/Confidence", value:100);

  report = report_items_str(report_items:report_items, ordered_fields:ordered_fields);

  security_report_v4(severity:SECURITY_NOTE, port:port, proto:proto, extra:report);

  exit(0);
}

# 1. SSH
esa_ssh = get_kb_item("Host/AsyncOS/Cisco Email Security Appliance");
ver_cmd = get_kb_item("Host/AsyncOS/version_cmd");
if (esa_ssh && !isnull(ver_cmd))
{
  matches = pregmatch(string:ver_cmd, pattern:'Version: ([0-9.-]+)');
  if (!empty_or_null(matches))
  {
    version = matches[1];

    matches = pregmatch(string:ver_cmd, pattern:'Model: (.+)');
    if (!empty_or_null(matches))
      model = matches[1];

    report_and_exit(ver:version, model:model, source:'SSH', port:0);
  }
}

# 2. HTTP
ports = get_kb_list('Services/www'); # forking is unlikely, but it will be avoided anyway

foreach port (ports)
{
  install = get_install_from_kb(appname:'cisco_esa', port:port);
  if (isnull(install)) continue;
  esa_http = TRUE;

  ver = install['ver'];
  if (ver == UNKNOWN_VER) continue;

  model = get_kb_item('cisco_esa/' + port + '/model');
  report_and_exit(ver:ver, model:model, source:'HTTP', port:port);
}

failed_methods = make_list();
if (esa_ssh)
  failed_methods = make_list(failed_methods, 'SSH');
if (esa_http)
  failed_methods = make_list(failed_methods, 'HTTP');

if (max_index(failed_methods) > 0)
  exit(1, 'Unable to determine ESA version number obtained via ' + join(failed_methods, sep:'/') + '.');
else
  exit(0, 'The ESA version is not available (the remote host may not be ESA).');
