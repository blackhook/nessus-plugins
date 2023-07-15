#TRUSTED 92b76fecad5626cb4933523b7698b8040fb20129982df8831e9207d95243f7830659a517a60038a2f651dc2861d9ac0162144f9e989c22edd630b12c1ab17677f997879d7a4acca104315034981cea1907e0c7c556873d29eb17c4d554ead160fc2251f3e4f130603bdd3c4947db550490a937634c0feb0005917722e0effbd19eaeecdc361d0a62c03d6de3a631dcca3f78c7f3373aaf0f0bd4542e5f428d9ff68bb5db7c8158fa3d14fc61e0e6730acd95279709fc4f316ea2b5fa86ea3f1f6ff7806e4a7e56209ac9e7ecdc0fa1b458cb8bba43b3852349072962c641779ca028d42850d0d4bd4916b00a4d53ab9836e2592f931dc493510b1c14d4e58460d1769c73515131a56c2fa97eaf87ca4e791f303bbec5324f852612914a3ea8127e7b0b4ce0c60afc7808cc632e31e63b1c7168bb3281dee419749a3dc6efd7261dc49a724021ef717ad470d5b5161760cb56bb2886c21c18d0d00979c39e2862a614c7c04b0be47ba5860939b18387385cc4935a190f5e353aa9cfdc6fdbade58db333aafc912306a0af6d2ad65d8eacd7d824bfce3fa47922a9265db0299fc93c1f38d7b9f8e0e5af4a01fb172fcdadda1ad991d794240244a8e4e9523e426c0df822245822e88bc0d3dc6c55d8e0ee6dc9a3fab41d199ecf9e97a376d499e403aa2bc39064c45c71db5dfda902302d6060eeca2ef6d8cf8dfd10d7d300d973
#TRUST-RSA-SHA256 757a8c02ad760c78d1c256d1e5cdbdabfe39139414b8d35e45a463b7d2113b2ecb2c91e8ac0de0c9a17d4855d20ffea18393ed06b4d2f8e552a0348f74ec37cab4f9befc2e9792f9fcf596f6d15faae7efd3f86d1de41a407ec0eb048b40afc8a79fcbb9c5dd6cef0867ca9712ac8f27d6169af4be797255785b18993f75ba780b3fa26016aaba96b81bf46e319ba05070271bd6bb2244823419a475b5f381079369e4cabdad97335824361f03a252c9660ea328677c6a697632946f8e51e14fde85a8913758df4c5bb7b5195db134e5a537ae9145544b9bde33a11ac711033d56ec8bc514ce041a25de6b3599fba85a58b86b0af3628a395f98139431a9f4ac431f38475e7b3a8030eb97ae59f7d8f21353ad5264879aabe015f1a29cd2e1fb81ad928c3a437f4a896ddc33d815d0c7e6ad4d2273834a794e1cd061fb1ef25e8f4edbdadd0f2a9653e2e436894bd7982bfef6aa5a31047945b0802d550915030ac075ede4ab25f4f0a149895c41ba7be2478e591c24536922230cdfadc12b060afbcf4da43309dce0d4f579b4213d5c82f5d84de946db0c2350faaaa7e3172ba609e6bf253cfa5476d7106dc47e174f421e39dd58aa1c4cd949e78634adc56a5bd109c33f80b35dbb929201f37e8374104266587cd6628ac72736c3b8d9bdcbf7caf3dc9c1fa8abee384d79a96f60dd3ec553e16ee6009542bf118e5dcaa60c
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(154138);
  script_version("1.07");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_name(english:"Oracle Cloud Infrastructure Instance Metadata Enumeration (Linux / Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is an OCI (Oracle Cloud Infrastructure) instance for which metadata could be
retrieved.");
  script_set_attribute(attribute:"description", value:
"The remote host is an OCI (Oracle Cloud Infrastructure) instance for which metadata could be
retrieved.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/ie/cloud/compute/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:oracle:cloud_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ifconfig_inet4.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("agent.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("http.inc");
include("local_detection_nix.inc");

if (sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

# Include global constants for interacting with the API
include('oci.inc');

var cmdline;
var oci_req_item = OCI_API_V1_ROOT;
var oci_req_header = {};

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
  var unsupported, supported, oskb;

  get_kb_item_or_exit('Host/local_checks_enabled');

  unsupported = TRUE;

  supported = make_list(
    'Host/CentOS/release',
    'Host/Debian/release',
    'Host/FreeBSD/release',
    'Host/Gentoo/release',
    'Host/Mandrake/release',
    'Host/RedHat/release',
    'Host/Slackware/release',
    'Host/SuSE/release',
    'Host/Ubuntu/release',
    'Host/Oralce/release'
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
    exit(0, 'Collection of OCI metadata via this plugin is not supported on the host.');

  info_connect(exit_on_fail:TRUE);
}

##
# Checks Oracle Cloud Infra indicators
##
function oci_platform_check()
{
  var pbuf, dirs, dir;

  pbuf = info_send_cmd(cmd:'/usr/bin/cat /run/cloud-init/ds-identify.log');
  if ('DMI_CHASSIS_ASSET_TAG=OracleCloud.com' >< pbuf) return TRUE;
  pbuf = info_send_cmd(cmd:'/usr/bin/cat /run/cloud-init/cloud-id');
  if ('oracle' >< pbuf) return TRUE;

  dirs = make_list( '', '/usr/sbin/', '/usr/local/sbin/', '/sbin/');
  foreach dir (dirs)
  {
    pbuf = info_send_cmd(cmd:strcat('LC_ALL=C ', dir, 'dmidecode -s chassis-asset-tag 2>&1'));
    if ('OracleCloud.com' >< pbuf) return TRUE;
  }

  if (ldnix::file_exists(file:'/etc/oracle-cloud-agent'))
    return TRUE;

  return FALSE;
}

function use_system_http_client(item, probe_cmd, v1_cmd, v2_cmd)
{
  var cmd, cmdt, buf, uri;
  cmdt =  "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy > /dev/null 2>&1; "; # Avoid using proxy
  cmdt += "export NO_PROXY=169.254.169.254 > /dev/null 2>&1; "; # Further attempt to avoid proxy 

  if (empty_or_null(item))
  {
    uri = OCI_API_ENDPOINT + OCI_API_V1_ROOT;
    # Determine IMDS version
    cmd = strcat(cmdt, probe_cmd, uri, 'instance 2>&1');
    spad_log(message:'Initial request to determine IMDS version: ' + obj_rep(cmd));
    buf = info_send_cmd(cmd:cmd);

    if ('404 Not Found' >< buf)
    {
      uri = OCI_API_ENDPOINT + OCI_API_V2_ROOT;
      cmdline = strcat(cmdt, v2_cmd, '"', OCI_IMDSV2_HEADER, '" ', uri);
    }
    else
    {
      cmdline = strcat(cmdt, v1_cmd, uri);
    }
    return buf;
  }

  if (!empty_or_null(item))
    cmd = strcat(cmdline, item, ' 2>&1');
  
  buf = info_send_cmd(cmd:cmd);

  return buf;
}

##
# For remote scans / agent scans
##
function use_curl()
{
  var curl_v1_cmd = 'curl -s -m 5 ';
  var curl_probe_cmd = 'curl -s -m 5 ';
  var curl_v2_cmd = curl_v1_cmd + ' -H ';

  return use_system_http_client(item:_FCT_ANON_ARGS[0], probe_cmd:curl_probe_cmd, v1_cmd:curl_v1_cmd, v2_cmd:curl_v2_cmd);
}

##
# For remote scans / agent scans on systems without curl
##
function use_wget()
{
  var wget_probe_cmd = 'wget -T 5 -O - ';
  var wget_v1_cmd = 'wget -q -T 5 -O - ';
  var wget_v2_cmd = wget_v1_cmd + '--header ';

  return use_system_http_client(item:_FCT_ANON_ARGS[0], probe_cmd:wget_probe_cmd, v1_cmd:wget_v1_cmd, v2_cmd:wget_v2_cmd);
}

##
# For local host scans
##
function use_send_recv3()
{
  var item, ret, headers;

  if (isnull(_FCT_ANON_ARGS[0]))
  {
    # Determine IMDS version
    ret = http_send_recv3(
      target       : OCI_API_HOST,
      item         : oci_req_item + 'instance',
      port         : 80,
      method       : 'GET',
      exit_on_fail : FALSE
    );
    spad_log(message:'Initial request to determine IMDS version (http_send_recv3): ' + obj_rep(ret[2]));

    if ('404 Not Found' >< ret[0])
    {
      oci_req_header = {
        'Authorization': 'Bearer Oracle'
      };

      oci_req_item = OCI_API_V2_ROOT;
    }
    return ret[0];
  }

  if (!empty_or_null(_FCT_ANON_ARGS[0]))
    oci_req_item += _FCT_ANON_ARGS[0];
  
  ret = http_send_recv3(
    target       : OCI_API_HOST,
    item         : oci_req_item,
    add_headers  : oci_req_header,
    port         : 80,
    method       : 'GET',
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
  var pbuf;
  if (info_t == INFO_LOCAL && !get_kb_item('nessus/product/agent'))
  {
    return @use_send_recv3;
  }
  else
  {
    # We prefer cURL over wget
    pbuf = info_send_cmd(cmd:'curl --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'curl --help' >< pbuf)
      return @use_curl;
    pbuf = info_send_cmd(cmd:'wget --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'wget --help' >< pbuf)
      return @use_wget;
  }
  return FALSE;
}

###
# Main
###

# Initialize command transport and determine how to talk to the API
init_trans();

if (!oci_platform_check())
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0,'OS information indicate the system is likely not an Oracle Cloud Instance.');
}

api_get_item = choose_api_function();
if (!api_get_item)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, 'There are no suitable methods for retrieving AMI data on the system.');
}

# Knowledge and xml tag bases
kbbase = OCI_KB_BASE;
xtbase = OCI_HOST_TAG_BASE;

buf = api_get_item();
if (empty_or_null(buf))
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1,'The remote host does not appear to be an Oracle Cloud Instance.');
}

apiresults = {};
success = [];
failure = [];

foreach apitem (OCI_API_ITEMS)
{
  buf = api_get_item(apitem);
  spad_log(message:strcat('Response of requesting ', apitem, ': ', obj_rep(buf)));

  if (empty_or_null(buf) || '404 (Not Found)' >< buf || '404 Not Found' >< buf || '404 - Not Found' >< buf || 'sh: 1' >< buf)
  {
    append_element(var:failure, value:apitem);
  }
  else
  {
    apiresults[apitem] = buf;
    append_element(var:success, value:apitem);
  }
}

if (info_t == INFO_SSH) ssh_close_connection();

# Do not report anything if all we get are failures
if ((max_index(success) == 0 || isnull(max_index(success)) && max_index(failure) > 0))
  exit(1,'The remote host does not appear to be an Oracle Cloud Instance.');

report = '';

# Check if the IP address gathered matches one of the host's IP addresses
# to ensure we did not retrieve a proxy's metadata
ips = get_kb_list('Host/ifconfig/IP4Addrs');

proxy_detected = FALSE;

pattern = 'privateIp' + '"' + "\s+:\s+" + '"' + "([\d+.]+)";
match = pregmatch(pattern:pattern, string:apiresults.vnics);
if (!isnull(match))
{
  metadata_privateip = match[1];
  if (!contains_element(var:make_list(ips), value:metadata_privateip))
  {
    proxy_detected = TRUE;
    report += '\nThe Oracle Cloud instance metadata below appears to be from a proxy due to the' +
              '\nIP addresses not matching any collected IP addresses.\n';
  }
}

if (max_index(success) != 0)
{
  report +=
  '\n  It was possible to retrieve the following API items :\n';

  foreach apitem (success)
  {
    pattern = "[\[\]{,}" + '"' + "]";
    foreach line (split(apiresults[apitem]))
    {
      line = ereg_replace(string:line, pattern:pattern, replace:'');
      if ( line !~ "^[\s\n]+$" )
        line = ereg_replace(string:line, pattern:"^(\s+)", replace:"  \1- ");
      report += line;
    }

    replace_kb_item(name:kbbase+"/"+apitem, value:apiresults[apitem]);
    report_xml_tag(tag:xtbase+"-"+apitem, value:apiresults[apitem]);
  }
}

if (max_index(failure) != 0)
{
  report +=
  '\n  The following items could not be retrieved :\n';
  foreach apitem (failure)
    report += '\n    - ' + apitem;
  report += '\n';
}

if (proxy_detected)
  replace_kb_item(name:kbbase+"/proxy_detected", value:TRUE);

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
