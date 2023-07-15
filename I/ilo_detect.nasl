#
# (C) Tenable Network Security, Inc.
#

# Modifications by Daniel Reich <me at danielreich dot com>
#
# - Added detection for HP Remote Insight ILO Edition II
# - Removed &copy; in original string, some versions flip the
#   order of Copyright and &copy;
# - Revision 1.2
#
# The above changes have since been removed.
# "HP Remote Insight ILO Edition II" mentioned above is a misspelling of
# "Remote Insight Light-Out Edition II" which is NOT iLO and is irrelevant.

include('compat.inc');

if (description)
{
  script_id(20285);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_name(english:"HP Integrated Lights-Out (iLO) Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is an HP Integrated Lights-Out (iLO) server.");
  script_set_attribute(attribute:"description", value:
"The remote host is an HP Integrated Lights-Out (iLO) server. These servers are embedded systems integrated into HP 
ProLiant servers for the purpose of out-of-band management.");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this host if you do not use it.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Service detection");

  script_require_ports("Services/www", 80, 443);
  script_dependencies("httpver.nasl", "broken_web_server.nasl");

  exit(0);
}

include('ilo_func.inc');

# Unfirewalled, there should be exactly 1 http & 1 https port.
# We retrieve a list and not branch because we are detecting whether or
# not the host server is iLO, not which ports are running the web interface.
var ports = get_kb_list("Services/www");

# By default, iLO listens on 80 and 443.
ports = add_port_in_list(list:ports, port:80);
ports = add_port_in_list(list:ports, port:443);

# Will track ports the interface is listening on.
# We may not have the firmware version until all ports are tried,
# so we delay calls to add_install.
var interface_ports = make_list();

var info = NULL;
foreach var port (ports)
{
  # If enabled, xmldata?item=all contains a superset of the data we could
  # retrieve by other means, so we try it first.
  var xml_info = detect_xmldata_all(port);

  # Not null signifies either that we were able to retrieve data or that
  # the remote host is iLO and the feature is disabled.
  if (!empty_or_null(xml_info))
    info = merge_hashes(info, xml_info);
  else # Now try /upnp/BasicDevice.xml
  {
    xml_info = detect_upnp_basic_device(port);
    if(!isnull(xml_info))
      info = merge_hashes(info, xml_info);
  }

  var more_info = NULL;
  if (isnull(info["generation"]))
  {
    if (is_ssl(port))
    {
      dbg::log(src:SCRIPT_NAME,msg:"XML not available. Trying via HTTPS");
      more_info = detect_https(port);
    }
    else
    {
      dbg::log(src:SCRIPT_NAME,msg:"XML not available. Trying via HTTP");
      more_info = detect_http(port);
    }

    info = merge_hashes(info, more_info);
  }

  if (!isnull(more_info) || !isnull(xml_info))
    interface_ports = make_list(interface_ports, port);
}

if (isnull(info))
  audit(AUDIT_NOT_DETECT, "HP Integrated Lights-Out");

# Backup method if XML does not identify Superdome.   
if (empty_or_null(info["server_model"]))
{
  var server_model, matches;
  var res = http_get_cache(port:port, item:"/");
    dbg::log(src:SCRIPT_NAME,msg:"cache output: " + obj_rep(info) + "\n");
  if ('HPE-iLO-Server' >< res)
  {
    matches = pregmatch(pattern:'[Ss]uperdome2', string:res, multiline:TRUE);
    if (!isnull(matches)) 
      info["server_model"] = matches[0];
  }
}

# This is a host OS detection
dbg::log(src:SCRIPT_NAME,msg:"info found: " + obj_rep(info) + "\n");
var extra = NULL;
if ( !empty_or_null(info["firmware"]) )
{
  extra["Version"] = info["firmware"];
}
host_os_add( method:"ilo_detect", os:"HP Integrated Lights-Out", confidence:95, type:"embedded", extra:extra );

# This information is about the host's firmware.
# Nothing is specific to the web interface,
# however info["firmware"] may be updated
# (and should be before the add_install() call)
foreach var key (make_list("generation", "firmware", "cardtype"))
{
  if (isnull(info[key]))
    continue;

  if (key == "firmware" && "F.0" >< info[key] && !isnull(info["cardtype"]) && info["cardtype"] == "Integrity")
  {
    set_kb_item(name:"ilo/firmware_full_version", value:info[key]);
    dbg::log(src:SCRIPT_NAME,msg:"Removing 'F.0' from firmware version " + info[key] + " due to detection of Integrity cardtype");
    info[key] = str_replace(string:info[key], find:'F.0', replace:'');
  }

  set_kb_item(name:"ilo/" + key, value:info[key]);
}

# Now that we have exhaustively attempted to find the firmware
# we record the existence of the web interface.
foreach port (interface_ports)
{
  replace_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

  # There can only be one version and instance of the web app, though
  # it may listen on multiple ports (max 1 http and 1 https). All settings
  # are the same across those ports.
  add_install(
    appname : "ilo",
    dir     : "/",
    port    : port,
    ver     : info["firmware"],
    cpe     : "cpe:/o:hp:integrated_lights-out"
  );

  if (info["sso"])
    set_kb_item(name:"www/ilo/" + port + "/sso_enabled", value:info["sso"]);
}

var is_moonshot = is_moonshot_device(ports:interface_ports);
if(is_moonshot)
  replace_kb_item(name:'www/ilo/moonshot', value:1);

var report = NULL;
if (report_verbosity && max_index(keys(info)) > 0)
{
  report = '\nHP Integrated Lights-Out (iLO)\n';

  if (!isnull(info["generation"]))
    report += '\n  Generation       : ' + info["generation"];

  if (!isnull(info["firmware"]))
    report += '\n  Firmware Version : ' + info["firmware"];

  if (!isnull(info["sso"]))
  {
    if (info["sso"])
      report += '\n  Single Sign-On   : Enabled';
    else
      report += '\n  Single Sign-On   : Disabled';
  }

  if (!isnull(info["server_model"]))
  {
    report += '\n\nAssociated ProLiant Server\n';
    report += '\n  Model : ' + info["server_model"];
    replace_kb_item(name:'www/ilo/server_model', value:info['server_model']);    
  }

  if(is_moonshot)
    report += '\n\nChassis : Moonshot iLO';
  report += '\n';
}

security_note(port:0, extra:report);
