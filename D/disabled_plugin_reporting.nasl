#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111754);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_name(english:"Deprecated / Disabled Plugins in Scan Policy - Notice");
  script_summary(english:"Reports recently disabled plugins.");

  script_set_attribute(attribute:"synopsis", value:
"Report on recently disabled plugins.");
  script_set_attribute(attribute:"description", value:
"One or more plugins that were enabled in the scan policy have been
either deprecated or disabled by Tenable with a notice to inform
customers of the change.

See plugin output for details on which plugin(s) enabled in the scan
policy have been deprecated or disabled and any other pertinent 
information. If you have any questions about the notice(s) or 
plugin(s) reported, please contact Tenable Support.

Note that not all deprecated or disabled plugins will have a notice
issued when they are deprecated or disabled, and notices will only be
active for a limited period of time.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_END2);

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Misc.");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("nessusd_product_info.inc");


# This is here to prevent license issues on SC and TIO.
# Because this plugin is run always and it would count
# against SC/TIO license we make sure that ports have been 
# detected on the target client which tells us the 
# target is a valid asset
tcp_ports = get_kb_list("Ports/tcp/*");
udp_ports = get_kb_list("Ports/udp/*");
if (!nessusd_is_agent() && isnull(tcp_ports) && isnull(udp_ports))
{
  exit(0, "No ports available, port detection prevents reporting on targets with no host-based scan results.");
}

disabled_plugin_report = "";

##
# Plugins disabled on 08/14/2018
# Reporting disabled till 08/25/2018
# see lt&l for more details
##
function disable_threatfeed_plugins(timestamp){
  local_var report;
  
  if (timestamp < unixtime()){
    return "";
  }
  
  report = "";
  
  if (is_plugin_enabled(script_family:"General", plugin_id:"52669")){
    report += 'Plugin 52669, Host is Listed in Known Bot Database\n';
    report += 'Summary : Checks if the IP of the remote host is listed in the IID db\n\n';
  }
  
  if (is_plugin_enabled(script_family:"General", plugin_id:"58429")){
    report += 'Plugin 58429, DNS Server Listed in Known Bot Database\n';
    report += 'Summary : Checks if the IP of a DNS server used by the remote host is listed in the IID db\n\n';
  }
  
  if (is_plugin_enabled(script_family:"General", plugin_id:"58430")){
    report += 'Plugin 58430, Active Outbound Connection to Host Listed in Known Bot Database\n';
    report += 'Summary : Checks netstat output to see if the host is connected to a host listed in the IID db.\n\n';
  }
  
  if (is_plugin_enabled(script_family:"General", plugin_id:"52670")){
    report += 'Plugin 52670, Web Site Links to Malicious Content\n';
    report += 'Summary : Checks if the IP of the remote host is listed in the IID db\n\n';
  }
  
  if (is_plugin_enabled(script_family:"General", plugin_id:"102425")){
    report += 'Plugin 102425, Active Inbound Connection From Host Listed in Custom Netstat IP Threat List\n';
    report += 'Summary : Uses results of nbin to report inbound custom ipthreat connections.\n\n';
  }
  
  if (is_plugin_enabled(script_family:"General", plugin_id:"102426")){
    report += 'Plugin 102426, Active Outbound Connection From Host Listed in Custom Netstat IP Threat List\n';
    report += 'Summary : Uses results of nbin to report outbound custom ipthreat connections.\n\n';
  }
  
  if (is_plugin_enabled(script_family:"General", plugin_id:"59713")){
    report += 'Plugin 59713, Active Inbound Connection From Host Listed in Known Bot Database\n';
    report += 'Uses results of nbin to report inbound botnet connections\n\n';
  }

  return report;
}


## Main 

disabled_plugin_report += disable_threatfeed_plugins(timestamp:1535500800);

if (strlen(disabled_plugin_report) > 0){
  security_note(port:0, extra:disabled_plugin_report);
  exit(0);
}

exit(0, "No recently disabled plugins detected during this scan.");
