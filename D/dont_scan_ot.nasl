###
#   (C) Tenable, Inc.
###

include("compat.inc");

if (description)
{
  script_id(109142);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_xref(name:"IAVB", value:"0001-B-0526");

  script_name(english:"Do not scan operational technology devices");
  script_summary(english:"Exclude operational technology devices from scan");

  script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be a fragile device and will not be
scanned.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be operational technology device. Such
devices often react very poorly when scanned. To avoid problems, Nessus
will not continue to scan this device.

If you would like to safely assess security vulnerabilities on this device,
Tenable suggests contacting your account representative to discuss employing Tenable.OT,
which is purpose built to address vulnerability management on devices of this type.
Note: OT devices often have nested interfaces or additional attached devices that
may not be accounted for in a traditional scan");

  script_set_attribute(attribute:"solution", value:
"If you are not concerned about such scan behavior, enable the 'Scan
Operational Technology devices' setting under 'Fragile Devices' in
the 'Host Discovery' section and then re-run the scan.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Settings");
  script_dependencies(
    "dont_scan_settings.nasl",
    "scada_profinet_network_detect.nbin",
    "scada_cip_list_identity.nbin",
    "scada_modbus_coil_check.nbin",
    "scada_bacnet_detect.nbin",
    "scada_siemens_simatic_s7_plc_detect.nbin",
    "scada_app_7t_igss_dc_detect.nbin",
    "scada_app_igss_odbc_detect.nbin",
    "scada_iccp_cotp_detect.nbin",
    "scada_omron_udp_detect.nbin",
    "scada_omron_tcp_detect.nbin",
    "scada_crimson_detect.nbin",
    "scada_dnp3_device_detect.nbin"
  );

  exit(0);
}

##
# Answers question "is OT scanning allowed?"
#
# @return TRUE if preference allows OT scans, FALSE otherwise
##
function ot_scanning_ok()
{
  local_var do_scans = get_kb_list("Scan/*");
  local_var otscan = do_scans["Scan/Do_Scan_OT"];
  return ( !isnull(otscan) && otscan );
}


##
#   Answer question "Are scanners configured?"
#
#   Improve Host Discovery speed by skipping
#    this plugin when no scanners are specified
#
#   Note: if this function is reached
#    dependencies have already been executed, unfortunately
##
function scanners_configured()
{
  if (isnull(get_kb_list("Host/scanners/*")) ||
      len(get_kb_list("Host/scanners/*")) == 0)
  {
    return 0;
  }
  return 1;
}

##
# Answers question "scan OT device?"
#
# @return TRUE if asset has detected ot protocol, FALSE otherwise
##
function dont_scan_ot_device()
{
 # KB accessor, existance of any ot protocol defaults to dont scan
 return has_ot_proto();
}

##
# Performs dont scan ot behaviors
#
# @return always returns NULL
##
function dont_scan_ot()
{
  if (!scanners_configured())
    return NULL;

  # NOT scanning OT in general? and dont scan ot device set?
  if ( !ot_scanning_ok() && dont_scan_ot_device( ) )
  {
    # general OT dont scan is not set (safe scanning enabled)
    # and this asset has indicated OT dont scan
    # mark the asset as dead, dont scan
    set_kb_item(name: "Host/dead", value: TRUE);
    # report host was marked dead
    # report global scan setting (its false)
    local_var extra = 'Operational Technology protocols identified:' + '\n';
    local_var proto_list = ot_proto_list( );
    local_var key = "";
    foreach key(keys(proto_list))
    {
      # report ot protocols detected (if any)
      extra = extra + key + '=' + proto_list[key] + '\n';
    }
    security_report_v4( port: 0, extra: extra, severity:SECURITY_NOTE );
  }
  return NULL;
}

dont_scan_ot();
