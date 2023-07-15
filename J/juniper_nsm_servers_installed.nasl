#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(69871);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_name(english:"Juniper NSM Servers Detection (credentialed check)");
  script_summary(english:"Detects Juniper NSM Servers.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host has one or more Juniper NSM servers installed."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus has determined that one or more Juniper NSM servers are
installed on the remote host."
  );
  # https://support.juniper.net/support/eol/#software
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f268744");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:netscreen-security_manager");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports('Host/NSM/guiSvr/version_src', 'Host/NSM/devSvr/version_src');
  exit(0);
}

include('local_detection_nix.inc');

ldnix::init_plugin();

var kb_base = "Host/NSM/";

var gui_svr_ver = get_kb_item(kb_base + 'guiSvr/version_src');
var dev_svr_ver = get_kb_item(kb_base + 'devSvr/version_src');

if (
  (isnull(gui_svr_ver) && isnull(dev_svr_ver)) ||
   (gui_svr_ver !~
      "guiSvrManager [a-zA-Z0-9.]+ \(Build LGB[a-zA-Z0-9]+\)" &&
    dev_svr_ver !~
      "devSvrManager [a-zA-Z0-9.]+ \(Build LGB[a-zA-Z0-9]+\)")
) audit(AUDIT_NOT_INST, "Juniper NSM Servers");

replace_kb_item(name:"Juniper_NSM_VerDetected", value:TRUE);

var item, report = '';

# Retrieving version information...
# guiSvrManager 2010.1 (Build LGB12z2cn)
# ...
if (gui_svr_ver =~ "guiSvrManager [a-zA-Z0-9.]+ \(Build LGB[a-zA-Z0-9]+\)")
{
  set_kb_item(name:kb_base + 'guiSvr/version_src', value:gui_svr_ver);
  item = eregmatch(pattern:"guiSvrManager ([a-zA-Z0-9.]+) \(Build (LGB[a-zA-Z0-9]+)\)",
                   string: gui_svr_ver);

  if (isnull(item)) exit(1, "Unexpected error parsing GUI Server version string.");

  set_kb_item(name:kb_base + 'guiSvr/version', value:item[1]);
  set_kb_item(name:kb_base + 'guiSvr/build', value:item[2]);

  report += '\n  GUI server version    : ' + item[1] +
            '\n  GUI server build      : ' + item[2] + '\n';
}

# Retrieving version information...
# devSvrManager 2010.1 (Build LGB12z2cn)
# ...
if (dev_svr_ver =~ "devSvrManager [a-zA-Z0-9.]+ \(Build LGB[a-zA-Z0-9]+\)")
{
  set_kb_item(name:kb_base + 'devSvr/version_src', value:dev_svr_ver);
  item = eregmatch(pattern:"devSvrManager ([a-zA-Z0-9.]+) \(Build (LGB[a-zA-Z0-9]+)\)",
                   string: dev_svr_ver);

  if (isnull(item)) exit(1, "Unexpected error parsing Device Server version string.");

  set_kb_item(name:kb_base + 'devSvr/version', value:item[1]);
  set_kb_item(name:kb_base + 'devSvr/build', value:item[2]);

  report += '\n  Device server version : ' + item[1] +
            '\n  Device server build   : ' + item[2] + '\n';
}

if (report_verbosity > 0) security_note(port:0, extra:report);
else security_note(0);
