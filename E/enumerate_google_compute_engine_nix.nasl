#TRUSTED 9b43967d8add30006e347cfa51bc804f1b52dc209715ba22a42c592ce272a49653a62859957c6539ceef0570653b1bac70c2dc314abc656d613729bd1720f74ca1d4d37d127f17fd4fabbbe8b242c9fb34ad566f6c6d9e3051e52704f7ea323eade2629d7fb5dc499eec80160c848f1b55597fc301894c67e51c95eb871ba8d7effef0208329d44068b84c63d4638b0fbc81456983a8d05d6dc6aaf10c9fecdaa43c3320a12732b6aabd86182570e56221ee7cb69a05ca6275922b55199fc6230a04e7ffba834241c891964935f0a7622156c4b9acdf5c591e7560661af3564112e0a090a49f29c5a4f20b5853925105dbaf2d44719305f925ccec3c3dbf015ffbabf2007a6fbfa1bc8c2cd9fc307519b70bfd8b6aa65b8c8849cd9099c042c83ca50f93b6d36ff2732f4d61a3f061e6037df44679343920306d8a095c08c53b5d7a18952eb54d9ef18b6ddc94af51f8a87215e560b8c5eb45b6953c3db589d00853d2c3b2f52261f9b05258572e51ca5b543a93c00916fa1f7147cadf5d60382579b9ffcb03a0d84a7db73ff1374fdb83a856102564e8672aa813a635b7a97bc518bf3bbb3748ba45ea714af3bbe24f91d42dc51fccc4d3c7291e2ffa5cc210f0336f7f206e432a78d730b6fcb65dbc98e0cf2b3efad30879f4e89fb8c459bd83808cce203a2ca503142c3b0bde85acb4e78c2eab50289daf8b609ca8172e35
#TRUST-RSA-SHA256 1fcc809d45d330806177d7d7aab209b60d0873f8d624d0b82a114fa9b8c508b3344fbc3f6512c2f15c45241026559e6d3abaf10010d9347d2c387df0bbba5bd4e9799778dc17b29502068a2764e24206a552ad26f17f29b03f7293f61808561e6333cad26070ee7a81e17540df6676bb1cd64daf7f8651b322f9497351671309f40dcc4ce703630b322a74fe46aa44e967afa4447cc0f3cb8108524cb217e53532afd9f70d2990324f0823be3353e7acd94b065b52079909b756ff7683dffd85ee586ea8b397f48df10e6fd2373ceb9422be38565f2e5aa30adf83725da10b96face88211a83633a767981f618048129b1f3291f55970cda753764dd016e1debc024b1eb60a181cc9c873845f4faf0fae05e18e0ab26646ded7040860750fdcd9be02109137b551d7e0ad75db623f00c38cc4474a5cfa395a5fc1686d345918ed637a1f497d94944b89c2eb1ec344e48579b8379533d1f2f72fadb82c900e8270bdf69ddcec92ec8ca0fa444e50ec9fcd4e41700f2486b2a70bceb70855c7d36cc61d6acf1d499be7184acfe5d9fb41d0584bedec80353e336721f0d394fc64312ab875c2f4266ac8ca317ba7b9c577a13bfa92470673f1da79260b02f2a90a6afb2081c547fad40b8d5f4c6579f0117611bb6f051f39ca298d4c198d63af0d70eaebf17a595d5beff8970f2a930b58973f0d05bc7f2773c5447f55264c08044
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99169);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Google Cloud Platform Compute Engine Instance Metadata Enumeration (Unix)");
  script_summary(english:"Attempts to retrieve Google Compute Engine metadata from a Unix-like operating system.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a Google Compute Engine instance for which metadata
could be retrieved.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Google Compute Engine instance. Nessus
was able to use the metadata API to collect information about the
system.");
  script_set_attribute(attribute:"see_also", value:"https://cloud.google.com/compute/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:google:compute_engine");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("http.inc");

if (sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

# Include global constants for interacting with the API
include("google_compute_engine.inc");

info_t = NULL;

###
# Establish transport for command running
#
# @remark Checks a list of "supported OS" kb items, and will
#         exit / audit on any failure that would not allow
#         us to continue the check.
#
# @return Always NULL
###
function init_trans()
{
  local_var unsupported, supported, oskb;

  get_kb_item_or_exit("Host/local_checks_enabled");

  unsupported = TRUE;
  # Remote OSes this check is supported on
  supported = make_list(
    "Host/Debian/release",
    "Host/CentOS/release",
    "Host/Ubuntu/release",
    "Host/RedHat/release",
    "Host/SuSE/release",
    "Host/Container-Optimized OS/release",
    "Host/AlmaLinux/release",
    "Host/RockyLinux/release"
  );

  foreach oskb (supported)
  {
    if (get_kb_item(oskb))
    {
      unsupported = FALSE;
      break;
    }
  }

  # Not a support OS, bail
  if (unsupported)
    exit(0, "Collection of Google Compute Engine metadata via this plugin is not supported on the host.");

  # Establish command transport
  if (islocalhost())
  {
    if (!defined_func("pread"))
      audit(AUDIT_FN_UNDEF,"pread");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (!sock_g)
      audit(AUDIT_FN_FAIL,"ssh_open_connection");
    info_t = INFO_SSH;
  }
}

###
# Logging wrapper for info_send_command
#
# @param cmd string command to run with info send command
#
# @return the output of the command
###
function run_cmd(cmd)
{
  local_var ret;
  spad_log(message:'Running command :\n'+cmd);
  ret = info_send_cmd(cmd:cmd);
  spad_log(message:'Output :\n'+ret);
  return ret;
}

##
# Checks the BIOS/Hypervisor info for Google Compute Engine
#
# @remark used to prevent unnecessary requests to API Host
#
# @return TRUE if check passed FALSE otherwise
##
function google_compute_engine_bios_check()
{
  local_var pbuf;
  # HVM
  pbuf = run_cmd(cmd:'cat /sys/devices/virtual/dmi/id/product_name');
  if ("Google Compute Engine" >< pbuf) return TRUE;
  else return FALSE;
}

##
# For remote scans / agent scans on systems without curl
##
function use_wget()
{
  local_var item, cmd, cmdt;
  cmdt = 'wget --header="Metadata-Flavor: Google" -q -O - {URI}';
  item = "http://"+GOOGLE_COMPUTE_ENGINE_API_HOST+GOOGLE_COMPUTE_ENGINE_API_ROOT;
  if (!empty_or_null(_FCT_ANON_ARGS[0]))
    item += _FCT_ANON_ARGS[0];
  cmd = ereg_replace(pattern:"{URI}", replace:item, string:cmdt);
  return run_cmd(cmd:cmd);
}

##
# For remote scans / agent scans
##
function use_curl()
{
  local_var item, cmd, cmdt;
  cmdt = 'curl --header "Metadata-Flavor: Google" -s {URI}';
  item = "http://"+GOOGLE_COMPUTE_ENGINE_API_HOST+GOOGLE_COMPUTE_ENGINE_API_ROOT;
  if (!empty_or_null(_FCT_ANON_ARGS[0]))
    item += _FCT_ANON_ARGS[0];
  cmd  = ereg_replace(pattern:"{URI}", replace:item, string:cmdt);
  return run_cmd(cmd:cmd);
}

##
# For local host scans
##
function use_send_recv3()
{
  local_var item, ret;
  item = GOOGLE_COMPUTE_ENGINE_API_ROOT;
  if (!empty_or_null(_FCT_ANON_ARGS[0]))
    item += _FCT_ANON_ARGS[0];
  ret = http_send_recv3(
    target       : GOOGLE_COMPUTE_ENGINE_API_HOST,
    item         : item,
    port         : 80,
    method       : "GET",
    add_headers  : make_array("Metadata-Flavor", "Google"),
    exit_on_fail : FALSE
  );
  # Return response body
  if (!empty_or_null(ret))
    return ret[2];
  return NULL;
}

###
# Choose the function we will use to get API data with
#
# @remark The agent must run curl / wget to retrieve these
#         items, plugins run by the agent are not allowed to
#         open any sockets.
#
# @return FALSE when no suitable method of calling the API can be found
#         A function pointer for one of the use_* functions defined above
##
function choose_api_function()
{
  local_var pbuf;
  if (info_t == INFO_LOCAL && !get_kb_item("nessus/product/agent"))
    return @use_send_recv3;
  else
  {
    # We prefer cURL over wget
    pbuf = run_cmd(cmd:'curl --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'curl --help' >< pbuf)
      return @use_curl;
    pbuf = run_cmd(cmd:'wget --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'wget --help' >< pbuf)
      return @use_wget;
  }
  return FALSE;
}

###
#  Report success / Create KB items
#  @remark A helper function to reduce code duplication
#
function report_success(apitem, buf)
{
    replace_kb_item(name:kbbase+"/"+apitem, value:buf);
    apitem_tag = str_replace(string:apitem, find: '/',  replace: "-");
    report_xml_tag(tag:xtbase+"-"+apitem_tag, value:buf);
    success = make_list(success, apitem);
    results[apitem] = buf;
}

# Initialize command transport and determine how to talk to the API
init_trans();

if (!google_compute_engine_bios_check())
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0,"BIOS information indicates the system is likely not a Google Compute Engine instance.");
}

api_get_item = choose_api_function();
if (!api_get_item)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "There are no suitable methods for retrieving Google Compute Engine metadata on the system.");
}

# Knowledge and xml tag bases
kbbase = GOOGLE_COMPUTE_ENGINE_KB_BASE;
xtbase = GOOGLE_COMPUTE_ENGINE_HOST_TAG_BASE;

# API items we want to get and their validation regexes
apitems = GOOGLE_COMPUTE_ENGINE_API_ITEMS;

# Check the API root first
buf = api_get_item();
if (isnull(buf) || "hostname" >!< buf || "network-interfaces/" >!< buf)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1,"The remote host does not appear to be a Google Compute Engine instance.");
}

# Now get each item we're interested in and validate them
success = make_list();
failure = make_list();
results = make_array();
foreach apitem (keys(apitems))
{
  buf = api_get_item(apitem);
  rgx = apitems[apitem];

  if (empty_or_null(buf) || buf !~ rgx)
    failure = make_list(failure, apitem);
  else
  {
    ##
    #  If we have obtained 'hostname' return data,
    #   we can also parse out 'Project ID' 
    ##
    if (apitem == "hostname")
    {
      apitem = "project-id";
      hostparts = make_list();
      hostparts = split(buf, sep:".", keep:FALSE);

      projectid = hostparts[(max_index(hostparts) - 2)];
      report_success(apitem:apitem, buf:projectid);

      # now resume, using the final report_success() call to save 'hostname' info
      apitem = "hostname";
    }

    ##
    #  Zone returns more information than needed
    #   'zone' will be saved in short form (ie: "us-east1-b")
    #   'full-zone' will be saved in long form
    #     (ie: "projects/152814345686/zones/us-east1-b")
    #   'project-num' will be saved as well
    #     (ie: "152814345686")
    ##
    if (apitem == "zone")
    {
      zoneparts = make_list();
      zoneparts = split(buf, sep:"/", keep:FALSE);
      actualzone = zoneparts[(max_index(zoneparts) - 1)];
      report_success(apitem:apitem, buf:actualzone);

      apitem = "project-num";
      projectnum = zoneparts[(max_index(zoneparts) - 3)];
      report_success(apitem:apitem, buf:projectnum);

      # now resume, using the final report_success() call to save 'full-zone' info
      apitem = "full-zone";
    }

    report_success(apitem:apitem, buf:buf);
  }
}

# For grabbing IP addresses. X and Y are indexes.
# Internals are at /network-interfaces/X/ip
# Externals are at /network-interfaces/X/access-configs/Y/external-ip
# GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST = "network-interfaces/";
# GOOGLE_COMPUTE_ENGINE_IP = "ip";
# GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST = "access-configs/";
# GOOGLE_COMPUTE_ENGINE_EXTERNAL_IP = "external-ip";
network_interfaces = api_get_item(GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST);
foreach interface (split(network_interfaces, keep:FALSE))
{
  # interface = "0/"

  # first grab internal ip
  # don't log failures, as this interface may not have an internal ip
  apitem = GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST + interface + "ip";
  internal_ip = api_get_item(apitem);
  if (!empty_or_null(internal_ip) && internal_ip =~ "^\d+\.\d+\.\d+\.\d+$")
  {
    replace_kb_item(name:kbbase+"/"+apitem, value:internal_ip);
    apitem_tag = str_replace(string:apitem, find: '/',  replace: "-");
    report_xml_tag(tag:xtbase+"-"+apitem_tag, value:internal_ip);
    success = make_list(success, apitem);
    results[apitem] = internal_ip;
  }

  # then try enumerating external ips
  access_configs = api_get_item(
    GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST +
    interface +
    GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST
  );
  foreach config (split(access_configs, keep:FALSE))
  {
    apitem  = GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST +
              interface +
              GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST +
              config +
              "external-ip";
    external_ip = api_get_item(apitem);
    if (!empty_or_null(external_ip) && external_ip =~ "^\d+\.\d+\.\d+\.\d+$")
    {
      replace_kb_item(name:kbbase+"/"+apitem, value:external_ip);
      apitem_tag = str_replace(string:apitem, find: '/',  replace: "-");
      report_xml_tag(tag:xtbase+"-"+apitem_tag, value:external_ip);
      success = make_list(success, apitem);
      results[apitem] = external_ip;
    }
  }
}

if (info_t == INFO_SSH) ssh_close_connection();

# Report successful retrievals
report = "";
if (max_index(success) != 0)
{
  report +=
  '\n  It was possible to retrieve the following API items:\n';
  foreach apitem (success)
    report += '\n    - '+apitem+': '+results[apitem];
  report += '\n';
}

# Report failures, should always be blank, mostly to help out CS
if (max_index(failure) != 0)
{
  report +=
  '\n  The following items could not be retrieved:\n';
  foreach apitem (failure)
    report += '\n    - '+apitem;
  report += '\n';
}

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);

