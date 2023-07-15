#TRUSTED 922b81817941d501f889e398020b3cd3726a7ef4c6d8028a28772aac36d8dbade3530d40036f80ac4446126633dac2b8559a2e8c0e5db7141f40d8feabc538a98669bb1495e8a41bfc06cfff2b4143fc41bcc9165a60d74c3ca9815866379d4a8b42597a965cb97d08586e13039c10b90d1394c7bf229facc56721564c3c76d2e3109bedb319b13a9f189aab3d065cf6559e0b7e39a33c6b58975472f827f47a56e0daab7bebd7b34b38eb60803fb0b54754952810e839f832ef076879f669a2da40a5bdf9b01026199901bc65b434f2ee11f88c3b1f85d4ab16bdcb33e3a25367491647dad860fa59b4c697aa33c4fc6644f0c0ad3fc66dc8ff1305c4479eed08a6886a8ca5e8f1442e750985ad8551db8a58bbefb7005c7409d4c29f16cdbc5b625586cc4a1ae83a6162a335eb673db7e04ada160d10e5a47f9db938aecfb411d3137e70a8ebba00e3c06e806aada7d11c1d4448b6c1dbc42ead18a714de2f4c5b7421b96329de038d62765fe99a86dc26e7ddeda64a35b368cc121b5cc58ae0199982bbae538ab04dc746bd7ec318d29e519b158dac72c50a9fc85916fbd6c5a49391751dd9fe28a75bb6b04c24beeed203d7a99d30cb85d7513d305e82bff3d739ed605924a4b1f38d0642905786a2afd7452831974eaea19869266d2d53c9b83e31afb52a812edaa82c32a8e016b897ce0dab1ab01f7934c3dbc341a383
#TRUST-RSA-SHA256 8470d859403501173969ca6e66e8aa37044353259f4bc8be04b48195deb4459c88666d450fba5730d174339bfacbe60fb9f3b4a34ae3dbce98a91fb080f229ca2cf768c1426604fdc0fcd55b3e366e531eddf59e31a905e5e058cf42009b931b0cfa588466d90a8dc1be58fa7205733918044ba7047bb5f3e3d1401c5f9273347c6e4d53df2da9b3acb778bc0b1f29a087dec2a09001c5a89023e864c2fd74b7dceefa73e707d34a8d2aeda3a33a84040276d956a9e0333ae73c215cd68b961c5c06a14458a3d54f9af68043c76c844bca365aaf985925144305a6a91ba6693ed3e9f76e919def99defb5c9c82e4dfb652a0672211fd6f0abf28c7fff2b4cc813fe24e087f51d9ca2c54d79809d3d01825d632619d1ad1b2084a171d6b0cc6490ee062686374a556e842577e8bf75a42016fd6ed378f47df1c2744d9cbd0bce354965fd1061b3c4df7760db9e087bf08118dd56e177d184ba0eacc0f05b05c76cb1ca327bf96c7047570640a02b844c5947500f73f8dfa47b93b23a229c6e5f6b9d7bcfe7d302e95c7095083c7640e2d06a7f5aee0ab7780a2691bfcc331a5df0a2341c152b7cd855937be8c2237f94358c6fa70fb4282a6f34e63b2a5f60c981abe3569a1989ba53f0f158cbdeb6f5f7a423ad823a6c921a254b96513398742b845cf408ae407fb05d302ccea1cd6d62b3d5800ff1d109b47ed4df8ea7f893d
###
# (C) Tenable Network Security, Inc.
#
###

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(160185);
  script_version("1.10");
  
  script_name(english:"Nutanix Data Collection");
  script_summary(english:"Collects Nutanix data.");

  script_set_attribute(attribute:"synopsis", value:"Collects all data from Nutanix PC using REST APIs.");
  script_set_attribute(attribute:"description", value:"Collects Nutanix data using REST APIs.");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:nutanix:pc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Misc.");

  script_dependencies("nutanix_settings.nasl");

  script_require_keys("Host/Nutanix/config/host", 
                      "Host/Nutanix/config/port", 
                      "Host/Nutanix/config/ssl", 
                      "Host/Nutanix/config/ssl_verify", 
                      "Secret/Nutanix/config/username", 
                      "Secret/Nutanix/config/password");

  script_timeout(0);

  exit(0);
}

if (!defined_func("inject_host") && defined_func("nasl_level") && nasl_level() <= 190200)
{
  exit(0, "Nessus older than 10.2");
}

include("compat_shared.inc");
include("http.inc");
include("nutanix.inc");
include("ssl_funcs.inc");
include("spad_log_func.inc");

if (defined_func("set_mem_limits")) 
{
  set_mem_limits(max_alloc_size:1024*1024*1024, max_program_size:1024*1024*1024);
}

##
# Wrapper for the collection and injection process.
##
function collect_nutanix_data()
{
  var config = nutanix::init();
  var hosts_to_inject = {};
  var nutanix_collection_host = get_host_ip();

  set_global_kb_item(name:"Nutanix/DataCollection/CollectionIP", value:nutanix_collection_host);

  # Optional Host Discovery
  if (config.auto_discovery_hosts)
  {
    nutanix::log(msg: '\n\nCollecting Hosts...\n', config:config);
    var host_list = nutanix::host_list(config:config);

    nutanix::log(msg: '\n\nEnumerating Hosts for Injection...\n', config:config);
    foreach (var host in keys(host_list))
    {
        set_global_kb_item(name:"Nutanix/Hosts/" + host, value:host_list[host]);

        nutanix::log(msg:"Discovered Nutanix Hypervisor: " + host + '\n', config:config);

        hosts_to_inject[host] = "Hypervisor";
    }
  }

  # Optional VM Discovery
  if (config.auto_discovery_vms)
  {
    nutanix::log(msg: '\n\nCollecting Virtual Machines...\n', config:config);
    var vm_list = nutanix::vm_list(config:config);

    nutanix::log(msg: '\n\nEnumerating Virtual Machines for Injection...\n', config:config);
    foreach (var vm in keys(vm_list))
    {
        foreach var ip (vm_list[vm])
        {
          nutanix::log(msg:"Discovered Nutanix VM: " + ip + '\n', config:config);

          hosts_to_inject[ip] = "VM";
        }
    }
  }

  nutanix::log(msg: '\n\nCollecting Cluster Info...\n', config:config);
  var cluster_info = nutanix::cluster(config:config);

  var cluster_count = 0;
  var cluster_skip_count = 0;

  foreach var cluster (cluster_info)
  {
    if (!empty_or_null(cluster.cluster_ip))
    {
      var ip_address = cluster.cluster_ip;
      var version = cluster.build.version;
      var full_version = cluster.build.full_version;
      var lts = cluster.build.is_long_term_support;
      var arch = cluster.cluster_arch;
      var service = cluster.cluster_service;
      var nodes = cluster.nodes;
      var software_map = cluster.software_map;

      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/ip", value:ip_address);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/version", value:version);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/full_version", value:full_version);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/lts", value:lts);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/arch", value:arch);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/service", value:service); 

      nutanix::log(msg:"Discovered Cluster IP: " + ip_address + '\n', config:config);
      nutanix::log(msg:"Discovered Cluster Version: " + version + '\n', config:config);

      nutanix::log(msg:"Discovered Cluster IP to Inject: " + ip_address + '\n', config:config);
      hosts_to_inject[ip_address] = "Cluster";

      nutanix::log(msg: '\nProcessing Cluster Software Map...\n', config:config);
      foreach var software (software_map)
      {
        var software_version = software.version;

        if (!empty_or_null(software_version))
        {
          var software_type = software.software_type;
          var software_status = software.status;

          set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/" + software_type + "/software_type", value:software_type);
          set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/" + software_type + "/software_version", value:software_version);
          set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/" + software_type + "/software_status", value:software_status);
        }
      }

      nutanix::log(msg: '\nProcessing Cluster Nodes...\n', config:config);
      foreach var node (nodes)
      {
        var node_ip = node.ip;
        var node_type = node.type;
        var node_version = node.version;

        set_global_kb_item(name:"Nutanix/Nodes/" + node_ip + "/ip", value:node_ip);
        set_global_kb_item(name:"Nutanix/Nodes/" + node_ip + "/version", value:node_version);
        set_global_kb_item(name:"Nutanix/Nodes/" + node_ip + "/type", value:node_type);

        hosts_to_inject[node_ip] = node_type;
      }

      cluster_count++;
    }
    else
    {
      # Count clusters without external IPs not sure what causes this
      cluster_skip_count++;
    }
  }

  nutanix::log(msg:"Discovered Cluster Count: " + cluster_count + '\n', config:config);
  nutanix::log(msg:"Discovered Cluster skipped Count: " + cluster_skip_count + '\n', config:config);

  var kb = { "host/injected/integration": "Nutanix" };

  # Centralized the collection of hosts and injections, since we pull hosts/vms from 3 locations
  foreach (ip in keys(hosts_to_inject))
  {
    nutanix::log(msg:"Injecting Discovered Nutanix " + hosts_to_inject[ip] + " -> " + ip + '\n', config:config);

    # Skip injecting 127.0.0.1, it is collected from Nutanix but should not be scanned this way.
    if ("127.0.0.1" >!< ip)
    {
      inject_host(hostname:ip, kb:kb);
    }
  }
}

mutex_lock(SCRIPT_NAME);

if (!get_global_kb_item("Nutanix/collected"))
{
  collect_nutanix_data();

  set_global_kb_item(name:"Nutanix/collected", value:TRUE);
}
else
{
  var collection_ip = get_global_kb_item("Nutanix/DataCollection/CollectionIP");
  spad_log(message:"Nutanix data has already been collected. Check results from " + collection_ip + " for the debugging log.");
}

mutex_unlock(SCRIPT_NAME);

var collected = get_global_kb_item_or_exit("Nutanix/collected", exit_code: 1, msg: "Data collection for Nutanix failed.");

if (!collected)
{
  var msg = "No information was collected from Nutanix Prism Central.";
  report_error(title:"Unable to collect Nutanix Prism Central data", message:msg, severity:1);

  exit(1, msg);
}

# Has Nutanix data collection already ran for this host?
if (!empty_or_null(get_kb_item("Host/Nutanix/DataCollection/ran")))
{
  exit(0);
}

# Current host we are running on for linking the collected data
var target_ip = get_host_ip();

var cluster_ip = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/ip");
var node_ip = get_global_kb_item("Nutanix/Nodes/" + target_ip + "/ip");
var nutanix_port = get_kb_item("Host/Nutanix/config/port");

var version, report;

# Reports cluster data
if (!empty_or_null(cluster_ip))
{
  var service = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/service");
  version = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/version");
  var lts = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/lts");
  var full_version = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/full_version");
  var arch = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/arch");

  set_kb_item(name:"Host/Nutanix/Data/Service", value:service);
  set_kb_item(name:"Host/Nutanix/Data/Version", value:version);
  set_kb_item(name:"Host/Nutanix/Data/lts", value:lts);
  set_kb_item(name:"Host/Nutanix/Data/ip", value:cluster_ip);
  set_kb_item(name:"Host/Nutanix/Data/full_version", value:full_version);
  set_kb_item(name:"Host/Nutanix/Data/arch", value:arch);

  report =
    'Collected Nutanix Data\n\n' +
    'Service: ' + service + '\n' +
    'Version: ' + version + '\n' +
    'Full Version: ' + full_version + '\n' +
    'LTS: ' + lts + '\n' +
    'Arch: ' + arch + '\n';

  security_report_v4(port:nutanix_port, extra:report, severity:SECURITY_NOTE);
}
# Reports node data
else if (!empty_or_null(node_ip))
{
  version = get_global_kb_item("Nutanix/Nodes/" + target_ip + "/version");
  var type = get_global_kb_item("Nutanix/Nodes/" + target_ip + "/type");

  set_kb_item(name:"Host/Nutanix/Data/Node/Ip", value:node_ip);
  set_kb_item(name:"Host/Nutanix/Data/Node/Version", value:version);
  set_kb_item(name:"Host/Nutanix/Data/Node/Type", value:type);

  report = 
    'Collected Nutanix Data :\n\n' +
    'IP Address: ' + node_ip + '\n' +
    'Version: ' + version + '\n' +
    'Type: ' + type + '\n';

  security_report_v4(port:nutanix_port, extra:report, severity:SECURITY_NOTE);
}

set_kb_item(name:"Host/Nutanix/DataCollection/ran", value:TRUE);
