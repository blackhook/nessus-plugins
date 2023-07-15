#TRUSTED 57a33df8629e8d5f6733e29908e4c03aac7e85423ef10fc58ecf75f691a812fed3fd28bb3b9263677ac59dc072375c01931f9b08cb6369764465a00a27ecee11ffc3eb2750801d304b152e129269167ce326336b92dd1124bb2e61c0da693b65560608f94457d0addb715b872ff138e2764eb947c04b2c74b50a2b6ec074314d02ee54da40e0a18db797380f5c3881b53483e93c307e3010b6e193acceccc550eee01d3bbb63add44926b57e1850a832a5956c752a985f1900055a6aadf83bb7c8f55701897df37d6d0f87da497d62e1c55640e53a98ae4e809b72f9f36296bd9822082491dabb1f87f814364f92fa5989ac8abd4412877988661ac7eb68ca776b652d895b3bde1c4dacdf3bbfa7467a40edce75dffeb4d456982bb08c6c786a5c1900497f64db21c955405a0c60e03ce6dd25010cf079e771816546f6889a2c222cdba6908d83216c29c3572296792ed34f55ebf96ad4a30a4f550d2d0ec8e04281cf0463ebb385836eff5d4d0ba33c462548f8026fac823163ef0657d74d1509f6400cc3ce4f34de01c78bc66860482e53f885483b2b5c3ca1aaca9a83a372b5247c1fba94178214029931282a90cff6b8eb594597a74f2efb9dfd61fc5b7ef594b2b4010397959e17fd94d264ddef9a446c98106317ce4d7afc903974b0168d1d6b404d28b5bdb79c4c22f484f7055546965bd1d278369da8bc0e3deceb47
#TRUST-RSA-SHA256 81c0540ad75c0f6471866dca6c472f85a1b1cd06eae34214a7f3deba4dec6f657282b67a3fda7a1852889f44146767e23ddcdef4e83110aec3fcca0eb412d692ebc4df5550f8fefbb3d78c1541c4562441f2c76e50006886fc12d6a1e83b15d213f9d5b89f56c942576d97839ed18ec393c7512739002825940c5e5fe661fbfbc0de3d47635582317e7d45d6cc0872ab1488dc700934d72353484f5b09437b3132c3f3e5539dbfd9f0343b78a4e6e277cf7c3929b82c7322cc338f3be371dd43ac827b8b26bf6cb97d6700a89b603706e2231b93d60cb81e7a062b0359887cf4833c22bd73ba77a9940f82ef22d908ceb3df5ad28e102c309879f5520ec258b30f17b3c063d57274e12e7f1434e22735183bc742994f6651336d55e061f151e32145faa0194c54310dc40bb51e31738ab34ea22dcf0f62d4098b96ff77676dadb86dd9ae35ee2598fc5ff5734a42f5731330bb4fc363b9ec21e43842d0ae9b2b03c2f2c05719dea8775137fa7388e9e3276cf65627e05aaae1df630fd68248a22b3004b5500de9fbaf96da58793f4972dc7994e96f2a912c9453e794e8f00eb89e764f04fc2891af54a842e3190655bd7b9720e7bd44ea8c6a842a728e3f155038b3bf640af98f016c4ef0629813759d5a3580bb30bcd6a606d8660af660a13509b02ee6a7ef3fe73a86f0eba8071358ead6c3f695a74f8bae1b8c2a872de55d

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150427);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/27");

  script_name(english:"Frictionless Assessment Asset Inventory");

  script_set_attribute(attribute:"synopsis", value:
"Nessus collected information about the network interfaces, installed software, users, and user groups on the target
host.");
  script_set_attribute(attribute:"description", value:
"Nessus collected information about the target host to create an inventory for Frictionless Assessment");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/09");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ifconfig_inet4.nasl", "ifconfig_inet6.nasl", "ifconfig_mac.nasl", "linux_alt_patch_detect.nasl", "redhat_repos.nasl");
  script_require_keys("Host/hostname", "Host/cpu");
  script_exclude_keys("Host/dead");

  exit(0);
}

include('rpm.inc');
include('debian_package.inc');
include('kpatch.inc');
include('ksplice.inc');
include('spad_log_func.inc');
include('nessusd_product_info.inc');
include('inventory_agent.inc');

##
# Generate normalized inventory packages list from KB data.
#
# @return array respresenting normalized inventory packages list.
##
function get_packages()
{
  # Get the package listing
  #'Host/FreeBSD/pkg_info',
  #'Host/Gentoo/qpkg-list',
  #'Host/HP-UX/swlist',
  #'Host/MacOSX/packages',
  #'Host/Mandrake/rpm-list',
  #'Host/McAfeeLinux/rpm-list',
  #'Host/OracleVM/rpm-list',
  #'Host/Slackware/packages',
  #'Host/Solaris/showrev',
  #'Host/Solaris11/pkg-list',
  #'Host/VMware/esxupdate',
  #'Host/VMware/esxcli_software_vibs',
  #'Host/XenServer/rpm-list',
  #'Host/Junos_Space/rpm-list'
  #'Host/AIX/lslpp',
  var pkg_mgrs = [
    'Host/AmazonLinux/rpm-list',
    'Host/CentOS/rpm-list',
    'Host/Debian/dpkg-l',
    'Host/RedHat/rpm-list',
    'Host/SuSE/rpm-list'
  ];
  
  var type, package, res, item;

  var package_inventory = [];
  foreach var pkg_mgr (pkg_mgrs)
  {
    var packages = get_kb_item(pkg_mgr);
    if (!empty_or_null(packages))
    {
      pkg_mgr = ereg_replace(pattern:'^.*/.*/(.*)', replace:"\1", string:pkg_mgr);
      switch (pkg_mgr)
      {
        case 'rpm-list':
          spad_log(message:'Found RPM packages.\n');
          type = 'rpm';
          packages = fixup_rpm_list(packages);
          foreach package (split(packages, sep:'\n', keep:FALSE))
          {
            res = parse_rpm_name(rpm:package);
            if (!empty_or_null(res['name']))
            {
              var epoch = '';
              if (!empty_or_null(res['epoch']) && res['epoch'] != '(none)')
              {
                epoch = res['epoch'] + ':';
              }
              var release = '';
              if (!empty_or_null(res['release']))
              {
                release = '-' + res['release'];
              }

              var version = epoch + res['version'] + release;
              item = make_array("type", type);
              item["properties"] = make_array("name", res['name'], 'version', version);
              append_element(var:package_inventory, value:item);
            }
          }
          break;
        case 'dpkg-l':
          spad_log(message:'Found DPKG packages.\n');
          type = 'dpkg';
          packages = _fixup_debian_dpkg_list(packages, keep_full_name:TRUE);
          foreach package (split(packages, sep:'\n', keep:FALSE))
          {
            res = NULL;
            res = _parse_debian_dpkg_name(dpkg:package, keep_full_name:TRUE);

            if (!isnull(res) && !empty_or_null(res['name']) && !empty_or_null(res['version']))
            {
              item = make_array("type", type);
              item["properties"] = make_array("name", res['name'], 'version', res['version'], 'metaname', res['metapackage']);
              append_element(var:package_inventory, value:item);
            }
          }
          break;
        default:
            continue;
      }
    }
  }
  
  return package_inventory;
}

##
# Generate normalized inventory kernel_patches based on kpatch/ksplice detections.
#
# @return kernel_patches item
##
function get_live_kernel_cves()
{

  var kernel_cves = make_array('type', 'kernel_patches');
  kernel_cves['properties'] = make_array('name', 'cves');
  kernel_cves['properties']['cves'] = [];

  var live_patch_type = 'kpatch';

  spad_log(message: 'Looking for kpatch CVEs.\n');
  var cves = kpatch_load_cve_list();
  if (isnull(cves))
  {
    spad_log(message: 'No kpatch CVEs found.\n');
    spad_log(message: 'Looking for ksplice CVEs.\n');
    live_patch_type = 'ksplice';
    cves = ksplice_load_cve_list();
    if (isnull(cves))
    {
      spad_log(message:'No ksplice CVEs found.\n');
      return kernel_cves;
    }
  }

  foreach var cve (keys(cves))
  {
    # Filter out kpatch/ksplice placeholder CVE of NONE and check the CVE is marked as applied.
    if (cve != "NONE" && cves[cve])
    {
      append_element(var:kernel_cves['properties']['cves'], value:cve);
    }
  }

  if (max_index(kernel_cves['properties']['cves']) > 0)
  {
    spad_log(message: 'Found ' + live_patch_type + ' CVEs.\n');
    return kernel_cves;
  }

  spad_log(message: 'No ' + live_patch_type + ' CVEs applied.\n');
  return kernel_cves;
}

##
# Get uptrack-uname -r output.
#
# @return uptrack-uname -r output or NULL if not found.
##
function get_uptrack_kernel_release()
{
  return get_kb_item("Host/uptrack-uname-r");
}

##
# Generate normalized inventory dnf_modules list from KB data.
#
# @return array respresenting normalized inventory dnf_modules.
##
function get_dnf_modules()
{
  var items = [];

  var dnf_modules = get_kb_list("Host/RedHat/modules/*");

  foreach var module (dnf_modules)
  {
    var item = make_array("type", "dnf_module");
    item["properties"] = make_array();

    foreach var line (split(module, sep:'\n'))
    {
      var matches = pregmatch(pattern: '^(.*)=(.*)$', string:line);
      if (!empty_or_null(matches))
      {
        if (!empty_or_null(matches[1]))
        {
          item["properties"][matches[1]] = default_if_empty_or_null(matches[2], default:'');
        }
      }
    }
    if (len(keys(item["properties"])) > 0)
    {
      append_element(var:items, value:item);
    }
  }

  return items;
}

##
# Generate normalized inventory pkg_repository items list from KB data.
#
# @return array respresenting normalized inventory pkg_repository items.
##
function get_package_repositories()
{
    var pkg_repo_items = [];
    var pkg_repo;

    var valid_repos_kb = get_kb_item('Host/RedHat/valid-repos');
    if (!empty_or_null(valid_repos_kb))
    {
      var valid_repos = deserialize(valid_repos_kb);
      foreach var repo(valid_repos)
      {
        pkg_repo = make_array("type", "pkg_repository");
        pkg_repo["properties"] = make_array("repo_label", repo);
        append_element(var:pkg_repo_items, value:pkg_repo);
      }
    }

    var valid_repo_urls_kb = get_kb_item('Host/RedHat/valid-repo-relative-urls');
    if (!empty_or_null(valid_repo_urls_kb))
    {
      var valid_repo_urls = deserialize(valid_repo_urls_kb);
      foreach var url (valid_repo_urls)
      {
        pkg_repo = make_array('type', 'pkg_repository');
        pkg_repo['properties'] = make_array('repo_relative_url', url);
        append_element(var:pkg_repo_items, value:pkg_repo);
      }
    }

    if (max_index(pkg_repo_items) > 0)
    {
      spad_log(message:'Found package repositories.\n');
    }
    else
    {
      spad_log(message:'No offical package repositories found. List of officially supported repos in rhel_repos.inc.\n');
    }

    return pkg_repo_items;
}


if (get_kb_item('Host/dead') == TRUE) exit(0, 'Host is offline.');
if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var system_hostname = get_kb_item_or_exit('Host/hostname');
var system_arch = get_kb_item_or_exit('Host/cpu');
var system_uname = get_kb_item_or_exit('Host/uname');
var system_kernel_release = get_kb_item_or_exit('Host/uname-r');

global_var DEBUG = get_kb_item("global_settings/enable_plugin_debugging");
global_var CLI = isnull(get_preference("plugins_folder"));

if (!CLI && !nessusd_is_offline_scanner())
{
  inventory_agent_or_exit();
}

# Required to store normalized inventory for the FA pipeline
if (!defined_func('report_tag_internal'))
  audit(AUDIT_FN_UNDEF, 'report_tag_internal');


# Check if distro is supported
spad_log(message:'Checking if distribution is supported.\n');
var supported_distros = ['Host/CentOS/release',
                         'Host/Ubuntu/release',
                         'Host/RedHat/release',
                         'Host/Debian/release',
                         'Host/AmazonLinux/release',
                         'Host/SuSE/release'];
var release = NULL;
var distro = NULL;
var name = NULL;
var matches;

foreach var supported_distro (supported_distros)
{
  release = get_kb_item(supported_distro);
  if (!isnull(release))
  {
    matches = pregmatch(pattern: '^Host/(.+?)/release$', string:supported_distro);
    if (!empty_or_null(matches))
    {
      name = matches[1];
      distro = tolower(name);

      
      if (distro == 'redhat')
      {
        # Oracle stores it's release data in Host/RedHat/release but can be detected with the following KB item.
        if (get_kb_item('Host/OracleLinux'))
        {
          name = "Oracle";
          distro = "oracle";
        }
        # Fedora stores it's release data in Host/RedHat/release but can be detected by looking for Fedora in the release string.
        else if ('fedora' >< tolower(release))
        {
          name = 'Fedora';
          distro = 'fedora';
        }
      }
      # Re-write distro for Amazon Linux to match what is expected by TVDL checks
      else if (distro == 'amazonlinux')
      {
        distro = 'amazon';
      }

      break;
    }
  }
}

if(isnull(release) || isnull(distro) || isnull(name))
{
  audit(AUDIT_OS_NOT, 'supported');
}

spad_log(message: 'Distro : ' + distro + '\nName : ' + name + '\nRelease : ' + release + '\n');


global_var asset_inventory = make_nested_array();
asset_inventory['source'] = 'NESSUS_AGENT';

# Initilize system block
asset_inventory['system'] = make_array();

# Set distro version info
spad_log(message: 'Set distribution version info.\n');
if ('fedora' == distro)
{
  matches = pregmatch(pattern: '^fedora.*release ([0-9]+)', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = 'FC' + default_if_empty_or_null(matches[1], default:'0');
  }
}
else if ('centos' == distro)
{
  matches = pregmatch(pattern: '^CentOS (?:Stream )?(?:Linux )?release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
    asset_inventory['system']['build'] = default_if_empty_or_null(matches[3], default:'0');
    if ('Stream' >< release)
    {
      distro = 'centos-stream';
    }
  }
}
else if ('ubuntu' == distro)
{
  matches = pregmatch(pattern: '^(\\d[\\d\\.]+)', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
  }
}
else if ('redhat' == distro)
{
  matches = pregmatch(pattern: '^Red Hat Enterprise Linux.*release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
    asset_inventory['system']['build'] = default_if_empty_or_null(matches[3], default:'0');
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('debian' == distro)
{
  matches = pregmatch(pattern: '^(\\d+)(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('oracle' == distro)
{
  matches = pregmatch(pattern: '^Oracle (?:Linux Server|Enterprise Linux) .*release (\\d+)(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('amazon' == distro)
{
  matches = pregmatch(pattern: '^AL(A|\\d)', string:release);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = "unknown";
    
    if (!empty_or_null(matches[1]))
    {
      if(matches[1] == "A")
      {
        asset_inventory['system']['version'] = "amzn1";
      }
      else if (matches[1] == "2")
      {
        asset_inventory['system']['version'] = "amzn2";
      }
    }
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('suse' == distro)
{
  # Check for SLES or SLED
  matches = pregmatch(pattern: '^SLE(S|D)(\\d+)', string:release);
  if (!empty_or_null(matches))
  {
    if (!empty_or_null(matches[1]) && matches[1] == "S")
    {
      distro = 'suse-server';
    }
    else if (!empty_or_null(matches[1]) && matches[1] == "D")
    {
      distro = 'suse-desktop';
    }
    
    var sp = string(get_kb_item("Host/SuSE/patchlevel"));

    asset_inventory['system']['version'] = default_if_empty_or_null(matches[2], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(sp, default:'0');
  }
  # Check for OpenSuSe
  else
  {
    matches = pregmatch(pattern: '^SUSE(\\d+)(?:\\.(\\d+))', string:release);
    if (!empty_or_null(matches))
    {
      distro = 'opensuse';
      asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
      asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0'); 
    }
    else
    {
      audit(AUDIT_OS_NOT, 'supported');
    }
  }
}
else
{
  audit(AUDIT_OS_NOT, 'supported');
}

spad_log(message:'Populate system block.\n');
asset_inventory['system']['name'] = name;
asset_inventory['system']['distro'] = distro;
asset_inventory['system']['hostname'] = system_hostname;
asset_inventory['system']['arch'] = system_arch;
asset_inventory['system']['os'] = 'linux';
asset_inventory['system']['uname'] = make_array();
asset_inventory['system']['uname']['kernel_release'] = system_kernel_release;
asset_inventory['system']['uname']['all'] = system_uname;

var feed_info = nessusd_plugin_feed_info();
spad_log(message: 'PLUGIN_SET : ' + feed_info['PLUGIN_SET'] + '\n');
# Default to old feed similiar to default in plugin_feed.info.inc
asset_inventory['system']['collection_version'] = default_if_empty_or_null(feed_info['PLUGIN_SET'], '20051108131841');

asset_inventory['items'] = [];

spad_log(message:'Populate packages.\n');

foreach var package(get_packages())
{
  append_element(var:asset_inventory['items'], value:package);
}

spad_log(message:'Populate dnf_module items.\n');

foreach var dnf_module(get_dnf_modules())
{
  append_element(var:asset_inventory['items'], value:dnf_module);
}

spad_log(message:'Populate pkg_repository items.\n');

foreach var pkg_repo(get_package_repositories())
{
  append_element(var:asset_inventory['items'], value:pkg_repo);
}


spad_log(message:'Populate live kernel CVEs.\n');
var kernel_cves = get_live_kernel_cves();
if (!isnull(kernel_cves))
{
  append_element(var:asset_inventory['items'], value:kernel_cves);
}

spad_log(message:'Populate uptrack kernel release.\n');
var uptrack_kernel_release = get_uptrack_kernel_release();
if (!isnull(uptrack_kernel_release))
{
  asset_inventory['system']['uptrack_kernel_release'] = uptrack_kernel_release;
}

spad_log(message:'Populate Product Items.');
var detected_products = get_detected_products();
if (!empty_or_null(detected_products))
  foreach var product_item(detected_products)
    append_element(var:asset_inventory['items'], value:product_item);

if (!nessusd_is_offline_scanner())
{
  spad_log(message:'Populate networks.\n');
  asset_inventory['networks'] = get_networks();
}

spad_log(message:'Inventory populated.\n');

# Save inventory
save_normalized_inventory(inventory:asset_inventory, is_cli:CLI, is_debug:DEBUG);
