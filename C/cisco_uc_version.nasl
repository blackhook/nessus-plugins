#
# (C) Tenable Network Security, Inc.
#

# @NOAGNT@

include("compat.inc");

if (description)
{
  script_id(70196);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0565");

  script_name(english:"Cisco Unity Connection Version");
  script_summary(english:"Gets the CUC version from SSH");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a Cisco Unity Connection.");
  script_set_attribute(attribute:"description", value:"Cisco Unity Connection was found.");

  script_set_attribute(attribute:"see_also", value:"https://www.cisco.com/c/en/us/products/unified-communications/unity-connection/index.html");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/OS/showver", "Host/Cisco/show_version_active");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_lib.inc");
include("ssh_func.inc");
include("install_func.inc");
include("spad_log_func.inc");

app_name = "Cisco VOSS Unity";

ret = get_kb_item_or_exit("Host/OS/showver");
spad_log(message:'Product kb data: ' + ret + '\n\n');

if (ret != "Cisco VOSS Unity (CUC)")
  audit(AUDIT_NOT_INST, app_name);

ret = get_kb_item_or_exit("Host/Cisco/show_version_active");
spad_log(message:'"show version active" results: ' + ret + '\n\n');


voss_pattern = "Active Master Version: ([0-9.-]+)";
version = pregmatch(string:ret, pattern:voss_pattern);
if (!empty_or_null(version) && !empty_or_null(version[1]))
  version = str_replace(string:version[1], find:"-", replace:".");
else
  version = UNKNOWN_VER;

extra_no_report = make_list();
extra = make_array();
patches = make_list();

lines = split(ret);
foreach line (lines)
{
  if (line =~ 'ciscocm.cuc.')
  {
    append_element(var:patches, value:chomp(line));
  }
}

extra_no_report = {'patches': patches};
spad_log(message:'extra_no_report: ' + obj_rep(extra_no_report) + '\n\n');
extra['Product'] = app_name;

register_install(
   app_name:app_name,
   vendor : 'Cisco',
   product : 'Unity Connection',
   path:'/',
   version:version,
   extra: extra,
   extra_no_report: extra_no_report,
   cpe:"cpe:/a:cisco:unity_connection");

report_installs(app_name:app_name, port:0);
