#TRUSTED 2e8720ecb81b36877fb73b26bf0a8aea2e2d62d06246485e2f547070561b28a02470eb85edc843a8a9a23fc8a3e231637470c8dd7a9aaec9e31a57d272b2abaecfb753542b2f67030a1cc9cc68f3eee1ed8699ba25d9505e6586cba36bd3eac925e4d792b80d777e244f0c9d03164ee5c3704c90348bc0ba0e246245238301210dff790ed6d8fba2a5c5a4b55be647199eca0ee4ad53bdd94ede879b29b38b9243eb92e4697e9873ee5c4bb989854be82c201662e80117f0f196c0e942f763dbca7e7b245ba96efedc15988d35f7a9b04f95e7584a0418f38717c328f038e99ef8778dccfeb09f03d0c336d5dad33ebc87ca05c27309fc94a086c7aa7bda80a9911a5bf11966100e29fb0f7c5837ef8c79c16c589b1a352f38b8a45360e9b4c9cbb0a0677c51a2b3e456451820207632ade009d3f054e98ef3bb53987023e6db5760ed1e6f80928b285a03bca2784f8a0219b8881688c923ec3b4ead2a308eea9037ffdeb320601732db79388af0808fdcda9cdf927889ad784c4159a348d708c5481e14359592a708732e76c16d62697a88c34f1f8b7b1986ccd8d78552501aa6a95dc2124a914c6def861bd7c0bc7d375c8e76a24e996e40a62f4d060cf1aa1c39dcfd886a1554dd69f712bf8f1f41d780923c4fcdf9f183a85e59502a627e3b5d27f00898de7517d42c7396ce4b1ddfff58e94e0635882669e39199381c9b
#TRUST-RSA-SHA256 4b6b4513119d6280cc28db58ab0522b7f77d5515c2bfd2f52943dd007a3fd4b732cf423a9ac7a768b8159a6d12ee214ff7933481d47f9e303dd19fd8634b9f7914f5a4457f211280a90cc1876dbf135df0cee1034ee71b3d9abb2666320397bae7922f636ac543b10978fb3e2dc4e514d77c866ac6072ad3f0bc55de58f75be745594a44e0c7bfd79abeb94148d635164161ac7b607f005f3fd36ec960369da298b6c7e8dae383ed2aece0eb03d7683c5debecc32ed189e84cc005d482bbc7d7a272d1d0ed35b7c3ce4c7150064b2b59542db8486c2ba8a908723365dcb9fe80c303efd9ee7e429107d92e19b7e19ff0da2f8a61c7259aca345d705b858568d22522bd36f2d2afa77b2115cb6281ef4151cd712b736dcdac516f0fd38e5d96980ec0f58b442a3b323f2b2c609cd8bce846e3d5de03629c868ece4726f25eac086652bfc8e503682f26b969bcce5aafd852b745baa3462722083fbb7a47ecf6301221fcb56cbbfc80959d37f422fa6c607c7ba500f73dacaea7e19030984c099d7854246d58317f661771a4efde59e543b7ac5c6fd89a52517b73e1c38dfc6518f91d795874136bcda1a23037d75e248bb97643d69ef65c6de42e4e410aae098c62e36df8550ea523c5daceeceadd218f7cc380ebbeed748e810739ae118b05520702f0028562e70923ca490afb00141eca6f388006344202716a7f203433941a
#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(19506);
  script_version("1.118");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/27");

  script_name(english:"Nessus Scan Information");

  script_set_attribute(attribute:"synopsis", value:
"This plugin displays information about the Nessus scan.");
  script_set_attribute(attribute:"description", value:
"This plugin displays, for each tested host, information about the
scan itself :

  - The version of the plugin set.
  - The type of scanner (Nessus or Nessus Home).
  - The version of the Nessus Engine.
  - The port scanner(s) used.
  - The port range scanned.
  - The ping round trip time 
  - Whether credentialed or third-party patch management
    checks are possible.
  - Whether the display of superseded patches is enabled
  - The date of the scan.
  - The duration of the scan.
  - The number of hosts scanned in parallel.
  - The number of checks done in parallel.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/26");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_END2);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_product_setup.nasl");

  exit(0);
}

include('nessusd_product_info.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');
include('agent.inc');

var rel, NESSUS6, nes_ver, nes_level, myVersion, plugin_feed_info, array, new_vers, list, version, unsupported_version,
acas_info, report, myPluginFeed, time, diff, old_feed, n_prod, scan_type, policy_name, policy_name2, range, ping_rtt,
modulus, local_checks, login_used, systemroot, proto_used, now, pmchecks, tool, report_superseded, opt, post_scan_editing,
start, zero, scan_duration, num_unsupported, i, cpe_base, old_feed_alert;

old_feed_alert = 0;
NESSUS6 = make_list(6,10,5);
nes_ver = nessus_version();
nes_level = NASL_LEVEL;
myVersion = NULL;

plugin_feed_info = nessusd_plugin_feed_info();

if(isnull(plugin_feed_info))
  plugin_feed_info = {};

if(isnull(plugin_feed_info["PLUGIN_SET"]))
  plugin_feed_info["PLUGIN_SET"] = "<error>";

if(isnull(plugin_feed_info["PLUGIN_FEED"]))
  plugin_feed_info["PLUGIN_FEED"] = "<error>";

if (!isnull(nes_ver))
{
  array = split(nes_ver, sep:'.', keep:FALSE);
  myVersion = make_list(int(array[0]), int(array[1]), int(array[2]));

  if ( myVersion[0] < NESSUS6[0] || (myVersion[0] == NESSUS6[0] && (myVersion[1] < NESSUS6[1] || (myVersion[1] == NESSUS6[1] && myVersion[2] < NESSUS6[2])))
  ) new_vers = NESSUS6[0] + "." + NESSUS6[1] + "." + NESSUS6[2];
}

#
# If no plugin has shown anything, exit and note
#
list = get_kb_list("Success/*");
if ( isnull(list) ) exit(0,"No scans were completed. No scan information to report.");


if ( ! strlen(nes_ver) )
{
  if ( ! defined_func("pread") && nes_level >= 2202 )
    version = "NeWT";
  else
    version = "Unknown (NASL_LEVEL=" + nes_level + ")";
}
else
  version = nes_ver;

unsupported_version = NULL;
if (!isnull(myVersion) && myVersion[0] < NESSUS6[0])
{
  unsupported_version = 'Your Nessus version ' + version + ' is no longer supported.\n' +
   'Please consider upgrading to ensure that results are complete.\n';
}

if ( new_vers )
 version += " (Nessus " + new_vers + ' is available.)\n';

var nasl_env = nasl_environment(flags:ENV_APP | ENV_RUNTIME | ENV_OS | ENV_SCAN);

acas_info = '';
report = 'Information about this scan : \n\n';
report += 'Nessus version : ' + version + '\n';
if (!empty_or_null(nasl_env.build))
  report += strcat('Nessus build : ', nasl_env.build, '\n');

if (!isnull(unsupported_version))
  report += unsupported_version + '\n';


if ( plugin_feed_info["PLUGIN_SET"] )
{
 if (  "Home" >< plugin_feed_info["PLUGIN_FEED"] )
   myPluginFeed = "Nessus Home";
 else
   myPluginFeed = "Nessus";

 report += 'Plugin feed version : ' + plugin_feed_info["PLUGIN_SET"]     + '\n';
 report += 'Scanner edition used : ' + myPluginFeed + '\n';
 set_kb_item(name: "PluginFeed/Version", value: plugin_feed_info["PLUGIN_SET"]);
 set_kb_item(name: "PluginFeed/Type", value: plugin_feed_info["PLUGIN_FEED"]);
 if ( plugin_feed_info["PLUGIN_SET"] =~ "^[0-9]*$" )
 {
  rel["year"] = int(substr(plugin_feed_info["PLUGIN_SET"], 0, 3));
  rel["mon"] = int(substr(plugin_feed_info["PLUGIN_SET"], 4, 5));
  rel["mday"] = int(substr(plugin_feed_info["PLUGIN_SET"], 6, 7));
  time = ((rel["year"] - 1970)*(24*3600*365)) +
	  (rel["year"] - 1970)/4*24*3600;
  time += (rel["mon"]-1)*(12*3600*30+12*3600*31);
  time += rel["mday"]*(24*3600);
  diff = (unixtime() - time)/3600/24;
  if ( diff >= 30 && diff < 10000 )
  {
   old_feed_alert ++;
   old_feed = '\nERROR: Your plugins have not been updated since ' +
     rel["year"] + "/" + rel["mon"] + "/" + rel["mday"] + '\n' +
'Performing a scan with an older plugin set will yield out-of-date results and
produce an incomplete audit. Please run nessus-update-plugins to get the
newest vulnerability checks from Nessus.org.\n\n';
   report += old_feed;
  }
 }
}

# Scanner OS
if (!empty_or_null(nasl_env.os))
  report += strcat('Scanner OS : ' + nasl_env.os, '\n');

if (!empty_or_null(nasl_env.distro))
  report += strcat('Scanner distribution : ', nasl_env.distro, '\n');

n_prod = get_kb_item("nessus/product");
if (!isnull(n_prod))
{
  if (n_prod == PRODUCT_WIN_AGENT  )      scan_type = "Windows Agent";
  else if (n_prod == PRODUCT_UNIX_AGENT ) scan_type = "Unix Agent";
  else if (n_prod == PRODUCT_MAC_AGENT )  scan_type = "Mac Agent";
  else if (n_prod == PRODUCT_NESSUSD    ) scan_type = "Normal";
  else if (n_prod == PRODUCT_NESSUSD_NSX) scan_type = "Nessus in NSX environment";
  else scan_type = "Nessus product undetermined";
  report += 'Scan type : ' + scan_type + '\n';
}

var scan_name;
if (!empty_or_null(get_preference('sc_scan_display_name')))
  scan_name = get_preference('sc_scan_display_name');
else if (!empty_or_null(nasl_env.scan_name))
  scan_name = nasl_env.scan_name;

if (!empty_or_null(scan_name))
  report += strcat('Scan name : ', scan_name, '\n');

policy_name = get_preference("@internal@policy_name");
if ( strlen(policy_name) > 0 )
{
  acas_info += 'ScanPolicy:' + policy_name;
  report += 'Scan policy used : ' + policy_name + '\n';
}

if (defined_func("report_xml_tag"))
{
  policy_name2 = get_preference("sc_policy_name");
  if (strlen(policy_name2) == 0) policy_name2 = policy_name;
  if (strlen(policy_name2) > 0) report_xml_tag(tag:"policy-used", value:policy_name2);
}

if (get_kb_item("Host/msp_scanner"))
{
  report += 'Scanner IP : tenable.io Scanner\n';
}
else
  report += 'Scanner IP : ' + compat::this_host()    + '\n';

var scanners;
if (!get_kb_item("nessus/product/local"))
{
  list = get_kb_list("Host/scanners/*");
  if ( ! isnull(list) )
  {
   foreach var item ( keys(list) )
   {
    item -= "Host/scanners/";
    scanners += item + ' ';
   }

   report += 'Port scanner(s) : ' + scanners + '\n';
  }
  else
   report += '\nWARNING : No port scanner was enabled during the scan. This may\nlead to incomplete results.\n\n';

  if ( get_kb_item("global_settings/disable_service_discovery") )
  {
   report += '\nWARNING: Service discovery has been disabled. The audit is incomplete.\n';
  }

  range = get_preference("port_range");
  if ( ! range ) range = "(?)";
  report += 'Port range : ' + range + '\n';
}

report += 'Ping RTT : ';
ping_rtt = get_kb_item("ping_host/RTT");
if (ping_rtt && ping_rtt > 0)
{
  modulus = ping_rtt % 1000;
  if (modulus == 0) modulus = "0";
  else if (modulus < 10) modulus = "00" + modulus;
  else if (modulus < 100) modulus = "0" + modulus;
  ping_rtt = (ping_rtt / 1000) + '.' + modulus + ' ms';
}
else
{
  ping_rtt = 'Unavailable';
}
report += ping_rtt + '\n';

report += 'Thorough tests : ';
if ( thorough_tests ) report += 'yes\n';
else report += 'no\n';

report += 'Experimental tests : ';
if ( experimental_scripts ) report += 'yes\n';
else report += 'no\n';

report += 'Plugin debugging enabled : ';
if ( !get_kb_item('global_settings/enable_plugin_debugging') ) report += 'no\n';
else report += 'yes (at debugging level ' + debug_level + ')\n';

report += 'Paranoia level : ';
report += report_paranoia + '\n';

report += 'Report verbosity : ';
report += report_verbosity + '\n';

report += 'Safe checks : ';
if ( safe_checks() ) report += 'yes\n';
else report += 'no\n';

report += 'Optimize the test : ';
if ( get_preference("optimize_test") == "yes" ) report += 'yes\n';
else report += 'no\n';

local_checks = FALSE;
login_used = get_kb_item("HostLevelChecks/login");

report += 'Credentialed checks : ';
if ( get_kb_item("Host/local_checks_enabled") )
{
  # 20220330: There are edge cases where SMB/not_windows will not write on a non-windows device,
  # but Host/windows_local_checks will write because it relies on SMB/not_windows.
  # Add another precautionary layer for a Host/Auth/SSH/*/Success KB key.
  if ( !get_kb_item("SMB/not_windows") && get_kb_item("Host/windows_local_checks") && empty_or_null(get_kb_list("Host/Auth/SSH/*/Success")) )
  {
    login_used = get_kb_item("HostLevelChecks/smb_login");
    #
    # Windows local checks are complex because the SMB Login *might* work but
    # access to C$ or the registry could fail
    #
    if ( get_kb_item("SMB/MS_Bulletin_Checks/Possible") )
    {
      local_checks = TRUE;
      report += 'yes';
      if (!isnull(login_used)) report += ", as '" + login_used + "' via SMB";
    }
    else
    {
      systemroot = hotfix_get_systemdrive(as_share:TRUE);
      if (get_kb_item("SMB/Registry/Enumerated") && (!isnull(systemroot) && get_kb_item("SMB/AccessibleShare/"+systemroot)))
      {
        local_checks = TRUE;
        report += 'yes';
        if (!isnull(login_used)) report += ", as '" + login_used + "' via SMB";
      }
      else
      {
        local_checks = FALSE;
        report += 'no';
      }
    }
  }
  else
  {
    # Not windows
    local_checks = TRUE;
    report += 'yes';

    # nb : from ssh_get_info.nasl
    proto_used = get_kb_item("HostLevelChecks/proto");
    if (!isnull(proto_used))
    {
      if (proto_used == 'local')
      {
        report += " (on the localhost)";
      }
      else if (!isnull(login_used))
      {
        report += ", as '" + login_used + "' via " + proto_used;
      }
      if ( nes_level >= 61100 )
      {
        report += '\nAttempt Least Privilege : ';
        if (get_kb_item("SSH/attempt_least_privilege")) report += 'yes';
        else report += 'no';
      }
    }
    # nb: from cisco_ios_version.nasl w/ SNMP
    else if (get_kb_item("Host/Cisco/IOS/Version"))
    {
      report += ", via SNMP";
    }
    # nb: from palo_alto_version.nbin, via REST API.
    else if (get_kb_item("Host/Palo_Alto/Firewall/Source"))
    {
      report += ", via HTTPS";
    }
  }
}
else if ( get_kb_item("SMB/MS_Bulletin_Checks/Possible") && !get_kb_item("Host/patch_management_checks") )
{
  local_checks = TRUE;
  report += 'yes';

  if (!isnull(login_used)) report += " (as '" + login_used + "' via SMB";
}
else report += 'no';
report += '\n';

if (defined_func("report_xml_tag"))
{
  now = unixtime();
  if (local_checks)
  {
    report_xml_tag(tag:"Credentialed_Scan", value:"true");
    report_xml_tag(tag:"LastAuthenticatedResults", value:now);
    acas_info += '\nCredentialed_Scan:true';
    acas_info += '\nLastAuthenticatedResults:' + now + '\n';
  }
  else
  {
    report_xml_tag(tag:"Credentialed_Scan", value:"false");
    report_xml_tag(tag:"LastUnauthenticatedResults", value:now);
    acas_info += '\nCredentialed_Scan:false';
    acas_info += '\nLastUnauthenticatedResults:' + now + '\n';
  }
}

pmchecks = "";
if (get_kb_item("patch_management/ran"))
{
  tool = "";
  foreach tool (keys(_pmtool_names))
  {
    if (get_kb_item("patch_management/"+tool))
    {
      pmchecks += ", " + _pmtool_names[tool];
      if (local_checks || !tool) pmchecks += " (unused)";
      else tool = _pmtool_names[tool];
    }
  }
}
if (get_kb_item("satellite/ran"))
{
  pmchecks += ", Red Hat Satellite Server";
  if (local_checks) pmchecks += " (unused)";
}
report += 'Patch management checks : ';
if (pmchecks)
{
  pmchecks = substr(pmchecks, 2);
  report += pmchecks + '\n';
}
else report += 'None\n';

#Display superseded patches: no (supersedence plugin ran)
if (get_kb_item("Settings/report_superseded_patches"))
{
  report_superseded = "yes";
}
else
{
  report_superseded = "no";
}
if (get_kb_item("Launched/66334"))
{
  report_superseded += " (supersedence plugin launched)";
}
else
{
  report_superseded += " (supersedence plugin did not launch)";
}
report += 'Display superseded patches : ' + report_superseded + '\n';

report += 'CGI scanning : ';
if (get_kb_item("Settings/disable_cgi_scanning")) report += 'disabled\n';
else report += 'enabled\n';

report += 'Web application tests : ';
if (get_kb_item("Settings/enable_web_app_tests"))
{
 report += 'enabled\n';
 # Display web app tests options
 opt = get_kb_item("Settings/HTTP/test_arg_values");
 report += 'Web app tests -  Test mode : ' + opt + '\n';

 report += 'Web app tests -  Try all HTTP methods : ';
 if (get_kb_item("Settings/HTTP/try_all_http_methods"))
  report += 'yes\n';
 else
  report += 'no\n';

 opt = get_kb_item("Settings/HTTP/max_run_time");
 report += 'Web app tests -  Maximum run time : ' + (int(opt) / 60) + ' minutes.\n';
 opt = get_kb_item("Settings/HTTP/stop_at_first_flaw");
 report += 'Web app tests -  Stop at first flaw : ' + opt + '\n';
}
else report += 'disabled\n';

report += 'Max hosts : ' + get_preference("max_hosts") + '\n';
report += 'Max checks : ' + get_preference("max_checks") + '\n';
report += 'Recv timeout : ' + get_preference("checks_read_timeout") + '\n';

if ( get_kb_item("general/backported")  )
 report += 'Backports : Detected\n';
else
 report += 'Backports : None\n';


post_scan_editing = get_preference("allow_post_scan_editing");
if ( post_scan_editing == "no" )
	report += 'Allow post-scan editing : No\n';
else
	report += 'Allow post-scan editing : Yes\n';

start = get_kb_item("/tmp/start_time");

if ( start )
{
 time = localtime(start);
 if ( time["min"] < 10 ) zero = "0";
 else zero = NULL;

 report += 'Scan Start Date : ' + time["year"] + '/' + time["mon"] + '/' + time["mday"] + ' ' + time["hour"] + ':' + zero + time["min"] + ' ' + getlocaltimezone() + '\n';
}

if ( ! start ) scan_duration = 'unknown';
else           scan_duration = (unixtime() - start) + " sec";
report += 'Scan duration : ' + scan_duration + '\n';

if ( defined_func("report_error") && old_feed_alert )
{
 report_error(title:"Outdated plugins",
	      message:old_feed,
	      severity:1);
}

if(get_preference("sc_disa_output") == "true")
{
  num_unsupported = get_kb_item("NumUnsupportedProducts");
  if(isnull(num_unsupported)) num_unsupported = 0;

  if(num_unsupported > 0)
    report += 'Unsupported products :';

  for (i=0; i<num_unsupported; i++)
  {
    cpe_base = get_kb_item("UnsupportedProducts/"+i+"/cpe_base");
    version = get_kb_item("UnsupportedProducts/"+i+"/version");
    if(version == "unknown")
      report += '\n  UnsupportedProduct:' + cpe_base;
    else
      report += '\n  UnsupportedProduct:' + cpe_base + ':' + version;
  }

  if(num_unsupported > 0) report += '\n';

  report += acas_info;
}

if(get_kb_item("ComplianceChecks/ran"))
{
  if (get_kb_item("ComplianceChecks/scan_info"))
  {
    report += "Compliance checks: " + get_kb_item("ComplianceChecks/scan_info") + '\n';
  }
  else
  {
    report += 'Compliance checks: Yes\n';
  }
}

var malware_scanning_setting = get_preference("Malicious Process Detection[checkbox]:enable_malware_scanning");
if (malware_scanning_setting != "yes")
  report += 'Scan for malware : no\n';
else
  report += 'Scan for malware : yes\n';

if ( old_feed_alert && !defined_func("report_error") )
{
 if ( nes_level < 3000 ) security_hole(port:0, data:report);
 else security_hole(port:0, extra:report);
}
else
{
 if ( nes_level < 3000 ) security_note(port:0, data:report);
 else security_note(port:0, extra:report);
}
