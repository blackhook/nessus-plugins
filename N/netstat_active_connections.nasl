#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58651);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/29");

  script_name(english:"Netstat Active Connections");
  script_summary(english:"Find active connections with netstat");

  script_set_attribute(
    attribute:"synopsis",
    value:"Active connections are enumerated via the 'netstat' command."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This plugin runs 'netstat' on the remote machine to enumerate all
active 'ESTABLISHED' or 'LISTENING' tcp/udp connections.

Note: The output for this plugin can be very long, and is not shown by default. To display it, enable verbose reporting in scan settings."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("netstat_portscan.nasl", "wmi_netstat.nbin");

  exit(0);
}
include('audit.inc');
include('misc_func.inc');
include('global_settings.inc');
include('network_func.inc');
include('data_protection.inc');

if(report_verbosity < 2)
{
    exit(0, 'This plugin only displays output if verbose reporting is enabled.');
}

var netstat = get_kb_item('Host/netstat');
if (isnull(netstat))
  netstat = get_kb_item('Host/Windows/%SystemRoot%\\System32\\netstat.exe_ano');
if (isnull(netstat))
  netstat = get_kb_item('Host/Windows/%SystemRoot%\\System32\\netstat.exe_an');
if (isnull(netstat))
  exit(0, 'No netstat output was found in the KB.');

var public_ips = make_array();
var lines = split(netstat, keep:FALSE);

var report_info = '';

var write_output = TRUE;

foreach var line (lines)
{
  if ('active' >< tolower(line) && 'socket' >< tolower(line))
    write_output = FALSE;

  if (write_output)
        report_info += line + '\n';
}

if (report_info != '')
{
  # Disable if data protection is filtering ip addresses
  data_protection::disable_plugin_if_set(flags:[data_protection::DPKB_IPADDR]);

  var report = '\nNetstat output :\n';
  report += report_info;
  security_note(extra: report, port:0);
}
else exit(0, 'No active connections were discovered.');

