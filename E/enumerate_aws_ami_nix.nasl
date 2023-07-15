#TRUSTED 95540f30a625c9909f49fc2301e6df8829425c82d3faf917afed5400ee561ee2e353f73e22aecf1b22026a099aa90741cdaecbaff153eafbebc5725eec2c032283a83ef08943f98eb05e088fc31f32fb7c7cdcd05e1bef501c2bfc741c5dbcd0cc5da127be939be768e290ce84f8addc259a743069b4a817bac26dc56211278e2d4e4224f36a2bf64643c0eb80ddd3154eda9c0675b06aa3802ca5444000564d1fd6030214301e16ea6e79a69a6713fe75e2cac561002f41d52be1774a01aff3d46b60a309d2bcc00f937af83c13a2c71a747bdbfd5b2ddbfb624b2389a93af6126dc7915b3c7e50969bd20ed2311d23f5a3899b8144d2193ca725460dc69111033d2c746e20546c8b10b003d6bdc691be23a90fc6a258ec09e83fa47b2553bf39e5d066004d622bca24775ee6da5dc20dc867392fe827218b52384609c5683237ebd965ea7180511dc8bd68108d17be5eea6271726230e0256e4333fd61ce4785c609895586020ab47887b201a3fdeb960818a683141aa53362e416d67726ef00f74458209b958413b9e03396cd108983c0b4b2fa1d3ca7902946a30e2f8e8b67b803c8c1c99a99ee2e1a51c09405e4b985ca1651862ec184cf1fdebad0a91ffadcf452fa770e36ccfda9b098bc938e01ce3ac2370b0bb3daacbe345920f99a764070cf760fc21b62a2849c078f9e02a652ce7a2fb50aee36da45b7d6b00041
#TRUST-RSA-SHA256 61925d0eb592cc7eb5743efab7732d0031e006a5c6b540dbd4de34fef33d6b08e41662893d00a5095c73193adeb48661f9f652eff9fabf3272b67a9b90acbdb30a3877b1421ecdbd10a23c807bad2ba228cdfb1af3ba103344357e4854e837037640458bf1a05ea1ed3e2a7d9074cf4dcb4d8959b18fd76f5fc4a7f3dab27258b502f49609ec03e9a0e17efd7d0da545f4dce035618fb3367f57767a3da7bd2e4f7abc0040e17075067d0b353a4a23fee99d6c51a0065b50c946ef76fe6cd4925b7f72c1272c7739a8921a375e98519bfe58212753c6940fa696d0eb5f7bd5161097d74e45db8ae7b282df6d1cec72817e73772408e81a4d26fc8b98f048a6367752a9c9d2cff62606979786aa6a0ed61bd2c8b5687a86413a491a251f886580b484c57752041f21c3e36ad949c9ff3426e437b354d6a1f3eb6d0c177e1913fdcc6b4862206472db0013e29a1952cabcc5c1f9e0d82e731133c09c731f71c58fab7cfad92f7b25d0f0ca653a4d379727050170b5abd4d2174b39b2e5966c0eb7e4eb461c6be7609051a1de2c4e30b3a59f53dc9f449aac08e364c138540c5e11aebecbb9a105b02589e94d37d765c66a9e91c11eea08c8c118b3baffd071888a8083382ba08d5c1c61f4136dcb61cf9ece782787d6f3883aacbbc5f360d737e7383fd41c903c7f48f2f65c6021bab6caaecf4428a721df3afff4b53467a48a7d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90191);
  script_version("1.47");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/07");

  script_name(english:"Amazon Web Services EC2 Instance Metadata Enumeration (Unix)");
  script_summary(english:"Attempts to retrieve EC2 metadata from a Unix like operating system.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is an AWS EC2 instance for which metadata could be
retrieved.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be an Amazon Machine Image. Nessus was able
to use the metadata API to collect information about the system.");
  script_set_attribute(attribute:"see_also", value:"https://docs.aws.amazon.com/ec2/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:amazon:ec2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bios_get_info_ssh.nasl", "ifconfig_inet4.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("agent.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("http.inc");

if (sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

# Include global constants for interacting with the API
include("amazon_aws_ami.inc");

var imdsVerDetermined = FALSE;
var tokenSet = FALSE;
var token = NULL;
var headers = {};

# plugin execution default timeout 320s
var maxtime = 320;

# Use 'timeout.90191' scanner setting if set
var timeout_override = get_preference('timeout.90191');
if (!empty_or_null(timeout_override))
{
  spad_log(message:'timeout.90191 preference set to ' + timeout_override);
  maxtime = timeout_override;
}

var gathertime = ((int(maxtime)/5) * 4);

var time_expired = FALSE;
var cmdt =  "unset http_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy > /dev/null 2>&1; "; # Avoid using proxy
cmdt += "export NO_PROXY=169.254.169.254 > /dev/null 2>&1; "; # Further attempt to avoid proxy 

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
  # Remote OSes this check is supported on, should this only
  # be Host/AmazonLinux/release ?
  supported = make_list(
    "Host/AmazonLinux/release",
    "Host/CentOS/release",
    "Host/Debian/release",
    "Host/FreeBSD/release",
    "Host/Gentoo/release",
    "Host/HP-UX/version",
    "Host/Mandrake/release",
    "Host/RedHat/release",
    "Host/Slackware/release",
    "Host/Solaris/Version",
    "Host/Solaris11/Version",
    "Host/SuSE/release",
    "Host/Ubuntu/release",
    "Host/AIX/version"
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
    exit(0, "Collection of AWS metadata via this plugin is not supported on the host.");
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
# Checks the BIOS/Hypervisor info for an Amazon BIOS/version of Xen
#
# @remark used to prevent unnecessary requests to API Host
#
# @return TRUE if check passed FALSE otherwise
##
function amazon_bios_check()
{
  local_var kb_value, pbuf;

  # Check if DMI data has already been gathered
  kb_value = get_kb_item("BIOS/Vendor");
  if (kb_value =~ "Amazon EC2")
    return TRUE;
  
  kb_value = get_kb_item("Host/dmidecode");
  if (preg(string:kb_value, pattern:"(Vendor|Manufacturer): *Amazon EC2", icase:TRUE, multiline:TRUE))
    return TRUE;

  # HVM
  pbuf = run_cmd(cmd:'cat /sys/devices/virtual/dmi/id/uevent');
  if (pbuf =~ "amazon") return TRUE;
  pbuf = run_cmd(cmd:'cat /sys/devices/virtual/dmi/id/bios_version');
  if ("amazon" >< pbuf) return TRUE;
  pbuf = run_cmd(cmd:'dmidecode -s system-version 2>&1');
  if ("amazon" >< pbuf) return TRUE;

  # Paravirtualized AMIs
  pbuf = run_cmd(cmd:'cat /sys/hypervisor/version/extra');
  if ("amazon" >< pbuf) return TRUE;
  else return FALSE;
}

###
# Determines which API path to use: AWS_AMI_API_ROOT if not
# instance identity document which uses alternate endpoint
###
function api_get_item_wrapper()
{
  local_var result;
  if (_FCT_ANON_ARGS[0] == 'instance-identity-document')
    result = api_get_item(AWS_AMI_API_INSTANCE_IDENTITY_DOCUMENT);
  else
    result = api_get_item(AWS_AMI_API_ROOT + _FCT_ANON_ARGS[0]);
  return result;
}

##
# For remote scans / agent scans on systems without curl
##
function use_wget()
{
  local_var item, cmd;

  if ( !imdsVerDetermined )
  {
    # Determine IMDS version
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
    cmd = cmdt + 'wget -q -T 5 -O - http://' + AWS_AMI_API_HOST + AWS_AMI_API_ROOT + ' 2>&1';
    spad_log(message:'Initial request to determine IMDS version: ' + obj_rep(cmd));
    buf = run_cmd(cmd:cmd);
    spad_log(message:'Response from ' + cmd + ': ' + obj_rep(buf));

    # Instances with IMDBv2 return with a 401 HTTP status code or 200 HTTP status with an empty body response
    if ('401 Unauthorized' >< buf || empty_or_null(buf))
    {
      cmd = cmdt + 'wget -q -T 5 --method=PUT http://' + AWS_AMI_API_HOST + AWS_IMDSV2_TOKEN_URI + ' -H ' + '"' + AWS_IMDSV2_TOKEN_PUT_REQUEST_HEADER + '"' + ' 2>&1';
      token = run_cmd(cmd:cmd);
      spad_log(message:'Token returned: ' + obj_rep(token));

      if ("--method=PUT" >< token)
      {
        if (info_t == INFO_SSH) ssh_close_connection();
        exit(1, 'Failed to retrieve IMDSv2 token. ' + 
                'Sending HTTP PUT request is currently not supported by the program "wget" installed on this host.');
      }

      if (empty_or_null(token))
      {
        if (info_t == INFO_SSH) ssh_close_connection();
        exit(1, 'Failed to retrieve IMDSv2 token.');
      }
    }

    imdsVerDetermined = TRUE;
  }

  if (!tokenSet)
  {
    if(!empty_or_null(token))
    {
      local_var token_hdr = ereg_replace(pattern:"TOKEN", replace:token, string:AWS_IMDSV2_TOKEN_HEADER);
      cmdt += 'wget -q -T 5 --header="' + token_hdr + '" -O - {URI}';
    }
    else
    {
      cmdt += 'wget -q -T 5 -O - {URI}';
    }

    tokenSet = TRUE;
  }

  item = "http://"+AWS_AMI_API_HOST;
  if (_FCT_ANON_ARGS[0] == AWS_AMI_API_ROOT)
    return imdsVerDetermined;
  else
    item += _FCT_ANON_ARGS[0];

  cmd = ereg_replace(pattern:"{URI}", replace:item, string:cmdt);
  spad_log(message:'Requesting metadata: ' + obj_rep(cmd));
  return run_cmd(cmd:cmd);
}

##
# For remote scans / agent scans
##
function use_curl()
{
  local_var item, cmd;

  if (!imdsVerDetermined)
  {
    # Determine IMDS version
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
    cmd = cmdt + 'curl -s -m 5 http://' + AWS_AMI_API_HOST + AWS_AMI_API_ROOT + ' 2>&1';
    spad_log(message:'Initial request to determine IMDS version: ' + obj_rep(cmd));
    buf = run_cmd(cmd:cmd);
    spad_log(message:'Response from ' + cmd + ': ' + obj_rep(buf));

    # Instances with IMDBv2 return with a 401 HTTP status code or 200 HTTP status with an empty body response
    if ('<title>401 - Unauthorized</title>' >< buf || empty_or_null(buf))
    {
      cmd = cmdt + 'curl -s -m 5 -X PUT http://' + AWS_AMI_API_HOST + AWS_IMDSV2_TOKEN_URI + ' -H ' + '"' + AWS_IMDSV2_TOKEN_PUT_REQUEST_HEADER + '"' + ' 2>&1';
      spad_log(message:'The current EC2 instance only supports IMDSv2, sending PUT request for obtaining metadata token: ' + cmd);

      token = run_cmd(cmd:cmd);
      if(empty_or_null(token))
      {
        if (info_t == INFO_SSH) ssh_close_connection();
        exit(1, 'Failed to retrieve IMDSv2 token.');
      }
    }

    imdsVerDetermined = TRUE;
  }

  if (!tokenSet)
  {
    if(!empty_or_null(token))
    {
      spad_log(message:'IMDSv2 metadata access token: ' + token);
      local_var token_hdr = ereg_replace(pattern:"TOKEN", replace:token, string:AWS_IMDSV2_TOKEN_HEADER);
      cmdt += 'curl -s -m 5 -H "' + token_hdr + '" {URI}';
    }
    else
    {
      cmdt += "curl -s -m 5 {URI}";
    }

    tokenSet = TRUE;
  }


  item = "http://"+AWS_AMI_API_HOST;
  if (_FCT_ANON_ARGS[0] == AWS_AMI_API_ROOT)
    return imdsVerDetermined;
  else
    item += _FCT_ANON_ARGS[0];

  cmd  = ereg_replace(pattern:"{URI}", replace:item, string:cmdt);
  spad_log(message:'Requesting metadata: ' + obj_rep(cmd));

  return run_cmd(cmd:cmd);
}

##
# For local host scans
##
function use_send_recv3()
{
  var ret, res;
  var token_headers = {
        'X-aws-ec2-metadata-token-ttl-seconds': 21600
      };
  var item = '';
  
  if (!imdsVerDetermined)
  {
    # Determine IMDS version
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
    ret = http_send_recv3(
      target       : AWS_AMI_API_HOST,
      item         : AWS_AMI_API_ROOT,
      port         : 80,
      method       : "GET",
      exit_on_fail : FALSE
    );
    spad_log(message:'Initial request to determine IMDS version (http_send_recv3): ' + obj_rep(ret[2]));

    # Instances with IMDBv2 return with a 401 HTTP status code or 200 HTTP status with an empty body response
    if ('<title>401 - Unauthorized</title>' >< ret[2] || empty_or_null(ret[2]))
    {
      res = http_send_recv3(
        target       : AWS_AMI_API_HOST,
        item         : AWS_IMDSV2_TOKEN_URI,
        add_headers  : token_headers,
        port         : 80,
        method       : "PUT",
        exit_on_fail : FALSE
      );

      if (empty_or_null([res[2]]))
      {
        if (info_t == INFO_SSH) ssh_close_connection();
        exit(1, 'Failed to retrieve IMDSv2 token.');
      }

      token = res[2];
    }

    imdsVerDetermined = TRUE;
  }

  if(!empty_or_null(token) && empty_or_null(headers))
  {
    headers = {
      'X-aws-ec2-metadata-token': token
    };
  }

  # use api root for a bare request: get_api_item()
  if (_FCT_ANON_ARGS[0] == AWS_AMI_API_ROOT)
    return imdsVerDetermined;
  else
    item = _FCT_ANON_ARGS[0];

  ret = http_send_recv3(
    target       : AWS_AMI_API_HOST,
    item         : item,
    add_headers  : headers,
    port         : 80,
    method       : "GET",
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
  {
    return @use_send_recv3;
  }
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
# Main
###

var start_time = gettimeofday();

info_connect(exit_on_fail:TRUE);

# Initialize command transport and determine how to talk to the API
init_trans();

# Amazon Linux is built for EC2 so we can skip the BIOS checks
var check_bios = TRUE;
if (!isnull(get_kb_item("Host/AmazonLinux/release")))
  check_bios = FALSE;

# Basic EC2 checks before communication with API server
if (check_bios && !amazon_bios_check())
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0,"BIOS and Hypervisor information indicate the system is likely not an AWS Instance.");
}

api_get_item = choose_api_function();
if (!api_get_item)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "There are no suitable methods for retrieving AMI data on the system.");
}

# Knowledge and xml tag bases
var kbbase = AWS_AMI_KB_BASE;
var xtbase = AWS_AMI_HOST_TAG_BASE;

# API items we want to get and their validation regexes
var apitems = AWS_AMI_API_ITEMS;

# Check the API root first
var buf = api_get_item_wrapper();
if ( !imdsVerDetermined )
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1,"The remote host does not appear to be an AWS Instance.");
}


# Now get each item we're interested in and validate them
var apiresults = make_array();
var success = make_list();
var failure = make_list();
var difftime;

foreach var apitem (keys(apitems))
{
  difftime = datetime::timeofday_diff(begin:start_time, end:gettimeofday());
  if (int(difftime) > gathertime)
  {
    spad_log(message:strcat('Plugin execution time limit ',maxtime,'s has been reached. Saving data and proceed to reporting now.'));
    break;
  }

  buf = api_get_item_wrapper(apitem);
  var rgx = apitems[apitem];

  if (empty_or_null(buf) || buf !~ rgx)
    failure = make_list(failure, apitem);
  else
  {
    apiresults[apitem] = buf;
    if (apitem == 'instance-identity-document')
    {
      # break apart and record metadata from instance identity JSON
      #
      # {
      #   "devpayProductCodes" : null,
      #   "marketplaceProductCodes" : null,
      #   "availabilityZone" : "us-east-2c",
      #   "version" : "2017-09-30",
      #   "region" : "us-east-2",
      #   "instanceId" : "i-02970e5aab6f4a924",
      #   "billingProducts" : null,
      #   "instanceType" : "t2.micro",
      #   "privateIp" : "172.31.45.131",
      #   "imageId" : "ami-47e5bf23",
      #   "accountId" : "232578266044",
      #   "architecture" : "x86_64",
      #   "kernelId" : null,
      #   "ramdiskId" : null,
      #   "pendingTime" : "2017-12-12T16:40:07Z"
      # }
      foreach var line (split(buf, keep:FALSE))
      {
        var pattern = '"(.*?)"\\s+:\\s+"?(.*?)"?,?$';
        var json = pregmatch(pattern:pattern, string:line);

        if (!empty_or_null(json))
        {
          apiresults[json[1]] = json[2];
          success = make_list(success, json[1]);
        }
      }
    }
    else if(apitem == 'block-device-mapping')
    {
      process_block_device_mapping_data(data:buf, success:success, apiresults:apiresults, api_get_item:@api_get_item_wrapper);
    }
    else
    {
      success = make_list(success, apitem);
    }
  }
}

if (empty_or_null(apiresults))
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, 'Failed to retrieve any instance metadata, exiting now...');
}

# special case for vpc-id since it requires the mac address which is dynamic
var mac = apiresults["mac"];
if (mac =~ "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
{
  # valid mac
  var vpc_id = api_get_item_wrapper("network/interfaces/macs/" + mac + "/vpc-id");
  if (vpc_id =~ "^vpc-[A-Za-z0-9]+$")
  {
    # valid vpc-id
    apiresults["vpc-id"] = vpc_id;
    success = make_list(success, "vpc-id");
  }
  else failure = make_list(failure, "vpc-id");
}


if (info_t == INFO_SSH) ssh_close_connection();

var report = "";

# Check if the IP address gathered matches one of the host's IP addresses
# to ensure we did not retrieve a proxy's metadata
# Note: currently only IPv4 is supported
var ipv4_addresses = get_kb_list("Host/ifconfig/IP4Addrs");
var ip_address_matched = ip_address_check(apiresults:apiresults, ipv4_addresses:ipv4_addresses);

var proxy_detected = false;

if (!isnull(ip_address_matched) && !ip_address_matched)
{
  proxy_detected = true;
  report += '\nThe EC2 instance metadata below appears to be from a proxy due to the' +
            '\nIP addresses not matching any collected IP addresses.\n';
}

# Report successful retrievals
if (max_index(success) != 0)
{
  report +=
  '\n  It was possible to retrieve the following API items :\n';

  foreach apitem (success)
  {
    report += '\n    - '+apitem+': '+data_protection::sanitize_user_enum(users:apiresults[apitem]);

    # Don't register XML tag if it appears that the metadata from a proxy was received
    if (proxy_detected)
    {
      replace_kb_item(name:kbbase+"/proxy_detected", value:TRUE);
      continue; 
    }

    replace_kb_item(name:kbbase+"/"+apitem, value:apiresults[apitem]);
    report_xml_tag(tag:xtbase+"-"+apitem, value:apiresults[apitem]);
  }
  report += '\n';
}

# Report failures, should always be blank, mostly to help out CS
if (max_index(failure) != 0)
{
  report +=
  '\n  The following items could not be retrieved :\n';
  foreach apitem (failure)
    report += '\n    - '+apitem;
  report += '\n';
}

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
