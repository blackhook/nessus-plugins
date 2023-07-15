#TRUSTED 0ae28156f428fc59d09a5d863a785f25d0812400d7d74f0e6090d5213c79f57ba0e6e535ecdf0ee837e3ec014b0c711b75bfda094c38837b9da944d41c24e61b6a650f043403c6fafd29ba309c78adad3e7b6ccb9320cd3f6fe38f0526e2e726b92e9d1407f3abc33136355728f4f30f31ddff23895fec1c5de64316cd25132cd6057e42427c9b2dd95acb29cdac817b379bd5e16804552be83285836160af02beac739538ee4385d77a5d1286bbb9858a5c569fdd32ad4aeed15e3c43255a9090c44282b108cdbbf6a9f002036ae5722068aeabb33fe3e9d032d89651448e33d2b2a47e198c48780de4b6f88c553d4ec2f65c207fb474562e802c6a377af7b471890d699e1e7fccf4d4108f688ddab378077827faf3b712addf365ec990f3dac02a9844d29b724a1fb66f7590633058f8f25513ba9636db8067cc227dd92743bbaf6b195520a3cdb959a8a266bcfcb1d65697cc29734ce143ca7fb27a501ea960d0b08099821d3cd4d05e5d2b4d27060b9a7888ae3e86c6b4c3d3fb38419e2af81ae804a70e63705cd3eff5014590b2866d000b1814a550be4211c25fab15dd12a3a3b3da11de0919ca33bfa6e4773ad72356073bb9d85797bd194aedcc3b3ba60a055906f32059b2e281056b4760383c6d4d391b4509ecbb94103a738d1e5cf6ad912da9d01a2b07dd4a94db5f5510d7d6cd8d9c4d2bb1ecd35a0891d75643
#TRUST-RSA-SHA256 0cb08befc8aeeb8df77579f023065869be90bf5b57adc3d502dcf9161a2cce4a978d5210d467462746cdc2842d862e4b6ae5ee262a3a6d863e2dd425496019345c176e7e641c4acd53ae8178e6c4d0752b8b0043d20eb9fe0825013f1ff5ff1b36ac19e8091d09481baedc2bd6dbc4e028264595b16f4da4e0d0d2eab8beb74480c837065ccacca56e8896d100309d03b6cd671bb46e63760a2f90409646fe789fe9ec5f8283107d9a55806e6f61b5612684da2d8e1eda98e9744b4aaedcd1e5c85645f3f830b1a67187f01042d00994a966d6546378865ee6fd39758c82a9392273fbd3db83bfed18b338a5ea865692f38f193e420cb7735ef2fb1a42fa2b6f06b2cbc0e4ebc633f7399dcb2b32e128c05ac8720d70c806535e17b547891526ab2bc4960a87cc2ad4af7f5282804db688f5e84eddb72f4262b31a72478251c0c3bc7ce819463882c7bd2129b4951e32cae14ee933f3302437f951e6f6c963ab83afd275dff4ddb4050f8f993f7623a374a87682bd7079385b741c8386df44adfc846c61df9d320ecc7a08eed7f5a2c3148d7687e0c322fd3be4c4e75a7c6584d10fdebd216266506384574c9fd597885daa1b721343d54c65dfd6b57072b59352781c84b1cced4c381476a33295e67de0a3aa76eb3c2e0806327c5354a2dff1dcd4fcc8e84a957ed2649173d90a9b0b711a180af3e3b7ecd9cae15b7c52be98

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157327);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/28");

  script_name(english:"Frictionless Assessment Asset Inventory Windows");

  script_set_attribute(attribute:"synopsis", value:
"Nessus collected information about the network interfaces, installed software, users, and user groups on the target
host.");
  script_set_attribute(attribute:"description", value:
"Nessus collected information about the target host to create an inventory for Frictionless Assessment");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/02");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_system_hostname.nbin", "smb_check_rollup.nasl", "smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_exclude_keys("Host/dead");

  exit(0);
}

include('smb_hotfixes.inc');
include('spad_log_func.inc');
include('inventory_agent.inc');

##
# Convert MS Rollup of to version for comparision.
#
# @param  rollup MS Rollup date
#
# @return version string suitable for version comparison with ver_compare().
##
function rollup_to_version(rollup)
{
  if (rollup !~ "^[0-9]+_[0-9][0-9_]*$") return NULL;

  var segs = split(rollup, sep:'_', keep:FALSE);
  var month = segs[0];
  # Swap month and year
  segs[0] = segs[1];
  segs[1] = month;

  return join(segs, sep:'.');
}

##
# Generate normalized inventory ms_rollup item from KB data.
#
# @param rollup to specify the type of rollup data to report on.
# @return array respresenting normalized inventory ms_rollup item.
##
function get_rollup_data(rollup_item)
{
  var item = make_array("type", rollup_item);
  item["properties"] = make_array();

  var kb_latest_rollup = NULL;
  var rollups = NULL;

  # MS rollup data
  if (rollup_item == "ms_rollup")
  {
    kb_latest_rollup = get_kb_item('smb_rollup/latest');
    rollups = get_kb_list('smb_rollup/fa_info/*');
  }

  # NET rollup data
  if (rollup_item == "dotnet_rollup")
  {
    kb_latest_rollup = get_kb_item('smb_dotnet_rollup/latest');
    rollups = get_kb_list("smb_dotnet_rollup/fa_info/*");
  }
    
  var latest_rollup = NULL;
  var invalid_rollups_found = FALSE;

  # Get individual rollup information
  foreach var rollup_key (keys(rollups))
  {
    # Get rollup date
    var rollup = split(rollup_key, sep:'/', keep:FALSE);
    rollup = rollup[2];

    # patched;full_path;patched_version;file_version
    var rollup_data = split(rollups[rollup_key], sep:';', keep:FALSE);
    var patched = "false";
    if (rollup_data[0] == "1")
    {
      patched = "true";
    }
    if (len(rollup_data) >= 4 &&
        !empty_or_null(rollup_data[1]) &&
        !empty_or_null(rollup_data[2]) &&
        !empty_or_null(rollup_data[3]))
    {
      item["properties"][rollup] = make_array("patched", patched,
                                              "path", rollup_data[1], 
                                              "fixed_version", rollup_data[2], 
                                              "version", rollup_data[3]);
    }

    # Track latest patched rollup
    if (empty_or_null(kb_latest_rollup) && patched == "true")
    {
      var latest_rollup_version = rollup_to_version(rollup:latest_rollup);
      var rollup_version = rollup_to_version(rollup:rollup);

      if (!isnull(latest_rollup_version) && !isnull(rollup_version))
      {
        if (isnull(latest_rollup) ||
          ver_compare(ver:latest_rollup_version,
                      fix:rollup_version, strict:FALSE) < 0)
        {
          latest_rollup = rollup;
        }  
      }
      else
      {
        invalid_rollups_found = TRUE;
        spad_log(message: 'Invalid MS rollup date found when comparing "' + latest_rollup_version + '" and "' + rollup_version + '".');
      }
    }
  }

  # Use latest rollup from KB if available otherwise fallback to latest rollup from file patch info.
  if (!empty_or_null(kb_latest_rollup))
  {
    item["properties"]["date"] = kb_latest_rollup;
  }
  else if(!empty_or_null(latest_rollup))
  {
    item["properties"]["date"] = latest_rollup; 
  }
  else
  {
    if (invalid_rollups_found)
    {
      spad_log(message: 'No valid MS or .NET Rollups found on the host. See previous logs for details on invalid rollups.');
    }
    else
    {
      spad_log(message: 'No MS or .NET Rollups found on the host.');
    }
  }

  return item;
}

if (get_kb_item('Host/dead') == TRUE) exit(0, 'Host is offline.');
get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var system_name = get_kb_item_or_exit('Host/OS');
var system_hostname = get_kb_item_or_exit('Host/hostname');
var system_arch = get_kb_item_or_exit('SMB/ARCH');
var system_build = get_kb_item_or_exit('SMB/WindowsVersionBuild');

global_var DEBUG = get_kb_item("global_settings/enable_plugin_debugging");
global_var CLI = isnull(get_preference("plugins_folder"));

if (!CLI)
{
  inventory_agent_or_exit();
}

# Required to store normalized inventory for the FA pipeline
if (!defined_func('report_tag_internal'))
  audit(AUDIT_FN_UNDEF, 'report_tag_internal');

# Check if Windows version is supported
spad_log(message:'Checking if Windows version is supported.');
var os_version = get_kb_item_or_exit("SMB/WindowsVersion");
os_version = string(os_version);

var supported_os_versions = ['6.0', '6.1', '6.2', '6.3', '10'];
var os_version_supported = FALSE;

foreach var supported_version (supported_os_versions)
{
  if (os_version == supported_version)
  {
    os_version_supported = TRUE;
  }
}

if (!os_version_supported)
{
  audit(AUDIT_OS_NOT, 'supported');
}

var os_sp = get_kb_item('SMB/CSDVersion');
if (os_sp)
{
  os_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:os_sp, replace:"\1");
}
else
{
  os_sp = '0';
}


global_var asset_inventory = make_nested_array();
asset_inventory['source'] = 'NESSUS_AGENT';

spad_log(message:'Populate system block.');
asset_inventory['system'] = make_array();
asset_inventory['system']['name'] = system_name;
asset_inventory['system']['hostname'] = system_hostname;
asset_inventory['system']['arch'] = system_arch;
asset_inventory['system']['os'] = 'windows';
asset_inventory['system']['version'] = os_version;
asset_inventory['system']['sp'] = os_sp;
asset_inventory['system']['build'] = system_build;
asset_inventory['system']['systemroot'] = hotfix_get_systemroot();

var feed_info = nessusd_plugin_feed_info();
spad_log(message: 'PLUGIN_SET : ' + feed_info['PLUGIN_SET']);
# Default to old feed similiar to default in plugin_feed.info.inc
asset_inventory['system']['collection_version'] = default_if_empty_or_null(feed_info['PLUGIN_SET'], '20051108131841');

asset_inventory['items'] = [];

spad_log(message:'Populate MS Rollups.');
append_element(var:asset_inventory['items'], value:get_rollup_data(rollup_item:'ms_rollup'));

# .NET rollup
spad_log(message:'Populate .NET Rollups.');
append_element(var:asset_inventory['items'], value:get_rollup_data(rollup_item:'dotnet_rollup'));

spad_log(message:'Populate Product Items.');
var detected_products = get_detected_products();
if (!empty_or_null(detected_products))
{
  foreach var product_item(detected_products)
  {
    append_element(var:asset_inventory['items'], value:product_item);
  }
}

spad_log(message:'Populate networks.');
asset_inventory['networks'] = get_networks();

spad_log(message:'Inventory populated.');

# Save inventory
save_normalized_inventory(inventory:asset_inventory, is_cli:CLI, is_debug:DEBUG);
