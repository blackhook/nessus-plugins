#TRUSTED 899e750390e746d049fb9a22252e41466c2e0a3a4586001481995c1b91078df3d322961b1d8c11cab8f32e0ab1d24d7ab31eb5f9cd4cd7a565fe6167bba01a333dce53800b33ef049ec8c1fa9fc4f39f043d164fe479cb4e1a977a5305b6e22feb90447c616b87bf9ddb67a9db8fc063cbfb7fe2964c455da7c7fa719d755a1631c0aba7af8e15812b6d7e2112ca1ef21bdcb0f78e94bb7bc2addb40dbcad8ea9e77dc9fa7e5c661b49ccedae2303b38fa5524e2b2d583e3ae3a1da5972f0e74dde7ec4a5fd657146c20c7ca758ac9a6ed9ea21899df8da6d64748231b9650ca9a623cf64764feb11da11e45c76b317732b7d0062cb38e943ad2dd919932132cb7752886a0b579e06338cef1bc1d358caf6bf64c557cf5b6a4439536c102bfd29d483c63db7544c53557d6b09147e54095ac0968e9337c0cd162091d4f54d9e16bfb230a92d69f7dc6934b54f404f648c04780627ea17c8e1ab6587cc62096b42827d8ad68251a6036ebf45faacec57c1673bd6706ba4d23f63f0f5ad4d0842f09421ee4b59a0c5f856702c4ff2e77bb5e1259e7e7905ac9ec7c066e3d1d2e48ea69bd21c062b1cc69b59632e42d32e0e086090d15675d262eff27bcea4f31c64e34dbf2903137e20c11c6cce0e83763b90372b682c341bd8faca6d6da2acf23e90f845d0e38a1fad87584de9ae39ed01ce2871b3f3b320efb05a305e7645821
#TRUST-RSA-SHA256 06bf9250b1a7350823e881e5ee69a8ce4f4cc2f89ecd5285e966af7c7e3f1737d6dfc0fbc79acc5f7e58a845fcf855c790e5c8c4217b0a4fad5222c904e5edc1c7db12b46ae4cb67db7af649f3ab979696fb5fdca2b5c61fda23aa48f6c4cd9a0923297d1f3a3f43c7974598cb55bfbcdeaf8c9f866915600ace368c7851f1b2da2f8c604aa94d0662f365506af231e06ffe3f947268b20d8f26671d80484c28cff51da9b4868beba4bf2cf01c6e458111a4f80584cf21fcd6e2138a530a94f21739dfca7d4dcb3a2d689525f95e90d9a6ec9d2c31c48285ce7afaa8611e3dbca479fde18c2c208f66c142f43e1ad0d9718bce499335ee206b96d75332bcc666d07455083c14c56e12fb30659c8aaa78a675f45b180ec25b43abb5f1cc7c0a8352f06ca4a2c0094d878f18544ab22864fcf83ec2e28e7f132a9e566a6770ebdb7980e7c82edea03d9c1b0babeba85cd5a538ffab71bcea25173b472ec9e7e6633b19f0b7a747df53da58e1932b989b0e025e868f1c88515389208a98c4e562dc15b2d3f05200b714fd65af7f2a53535e195bcd401635b4cbbff7a86504c10ad45dea71d8cf267b2a2a5d11b20f85bdab7821753db91392625f262e69a7ce2f95ec90ae14ddbd347d0d8727827cd245b2bddc23aab2346598e80f3deea50c237bf038c92df66157d447a59335c5d37e29ee99d21745d0ca4af425791d327b2f26
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(83349);
  script_version("1.39");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_name(english:"Post-scan OS Identification");

  script_set_attribute(attribute:"synopsis", value:
"Processes and reports system information about the remote host.");
  script_set_attribute(attribute:"description", value:
"This plugin processes and reports on system information about the remote host detected by other plugins.
This information is used by Tenable products for informational and tracking purposes.

The main asset attributes processed in this plugin include:
  - OS
  - DNS Names
  - IP Address
  - MAC Addresses

In addition, this plugin generates additional OS fingerprinting data used by dashboards.

Note that this plugin does not produce output.");
  # https://docs.tenable.com/tenableio/Content/Explore/Assets/HostAssetDetails.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7e0a415");
  script_set_attribute(attribute:"see_also", value:"https://docs.tenable.com/tenablesc/Content/ViewHostDetails.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}

include("agent.inc");
include("resolv_func.inc");
include("mac_address_func.inc");
include("json2.inc");

##
## Check for data populated by os_fingerprint* plugins
##
var output = '';
var best_score = -1;
var invalid_fqdn_count = 0;

# Dynamically makes fingerprint method list
# We only care about ones with Confidence
var methods = make_list();

var OS_kbs = get_kb_list("Host/OS/*/Confidence");
var matches, misc, kb, score, best_meth;

if ( !isnull(OS_kbs) )
{
  foreach var kb_name (keys(OS_kbs))
  {
    matches = pregmatch(pattern:"Host/OS/(\w+)/Confidence", string:kb_name);
    if (isnull(matches)) continue;
        
    # Avoid creating Windows tag on non-Windows assets
    misc = tolower(get_kb_item('Host/OS/Misc'));
    if (matches[1] == 'smb' && get_kb_item('SMB/not_windows'))  # Host/OS/smb
      continue;
    if (matches[1] == 'Misc' && misc =~ 'windows' && get_kb_item('SMB/not_windows'))  # Host/OS/Misc
      continue;
      
    methods = make_list(methods, matches[1]);
  }

  methods = list_uniq(methods);

  foreach var meth (methods)
  {
    kb = get_kb_item("Host/OS/" + meth);
    if( kb )
    {
      score = get_kb_item("Host/OS/" + meth + "/Confidence");
      if ( isnull(score) ) continue;
      if ( score < best_score ) continue;
      best_score = score;
      best_meth  = meth;
    }
  }
}
else
  best_meth = "Unknown";

# MAC addresses - consolidate and set "Host/mac_addrs" KB
get_all_macs();

# virtual MAC addresses - consolidate and set "Host/virtual_mac_addrs" KB
get_virtual_macs();

## Set tags from dashboard_report_host_get_tags
## /Host/Tags/report/
var tag_host_ip = "";
var tag_host_fqdn = "";
var tag_host_rdns = "";

##
#  Report FQDN info from all data sources
#
#  variable tag_host_fqdns to contain json-formatted 'ds' data structure of this info
##
var tag_host_fqdns = "";
var ds = make_list();
var add = make_list();

# add 'hostname -A' output data to FQDN tracking data structure
var tag_host_hostname_A = get_kb_item("Host/hostname-A");
var tag_host_note = get_kb_item("Host/hostname-A_note");
var invalid_key;

if (tag_host_hostname_A &&
    ("invalid" >!< tag_host_note ||
     "not attempted" >!< tag_host_note))
{
  tag_host_hostname_A = chomp(tag_host_hostname_A);
  var names = split(tag_host_hostname_A, sep:" ", keep:FALSE);
  names = list_uniq(names);

  foreach var name (names)
  {
    if (!empty_or_null(name))
    {
      if (valid_fqdn(fqdn:name))
      {
        add.FQDN = name;
        add.sources = [ "hostname-A" ];
        append_element(var:ds, value:add);
      }
      else
      {
        invalid_key = "invalid_FQDN_" + invalid_fqdn_count;
        set_kb_item(name:invalid_key, value:name);
        invalid_fqdn_count++;
      }
    }
  }
}

# add the name specified in scan configuration
var report_name, found;

report_name = get_kb_item("Flatline/get_host_report_name");
if (empty_or_null(report_name))
  report_name = get_host_report_name();

if (valid_fqdn(fqdn:report_name))
{
  foreach var ds_item (keys(ds))
  {
    if (ds[ds_item].FQDN == report_name)
    {
      found = TRUE;
      append_element(var:ds[ds_item].sources, value:"get_host_report_name()");
    }
  }
  if (!found)
  {
    add.FQDN = report_name;
    add.sources = [ "get_host_report_name()" ];
    append_element(var:ds, value:add);
  }
}
else
{
  invalid_key = "invalid_FQDN_" + invalid_fqdn_count;
  set_kb_item(name:invalid_key, value:report_name);
  invalid_fqdn_count++;
}

# add agent/non-agent identity-related data
var legacy_val, rdns;
if (agent())
{
  if (!empty_or_null(agent_get_ip()))
    tag_host_ip = agent_get_ip();

  tag_host_fqdn = agent_fqdn();
  if (valid_fqdn(fqdn:tag_host_fqdn))
  {
    # Create backup of previous value if overwriting
    legacy_val = get_kb_item("myHostName");
    if (!empty_or_null(legacy_val) && legacy_val != tag_host_fqdn)
      set_kb_item(name:"myHostName_previous", value:legacy_val);
    replace_kb_item(name:"myHostName", value:tag_host_fqdn);

    # add agent data to FQDN tracking data structure
    found = FALSE;
    foreach ds_item (keys(ds))
    {
      if (ds[ds_item].FQDN == tag_host_fqdn)
      {
        found = TRUE;
        append_element(var:ds[ds_item].sources, value:"agent_fqdn()");
      }
    }
    if (!found)
    {
      add.FQDN = tag_host_fqdn;
      add.sources = [ "agent_fqdn()" ];
      append_element(var:ds, value:add);	
    }
  }
  else
  {
    invalid_key = "invalid_FQDN_" + invalid_fqdn_count;
    set_kb_item(name:invalid_key, value:tag_host_fqdn);
    invalid_fqdn_count++;
  }
}
else
{
  if (defined_func("get_host_ip") && get_host_ip() != NULL)
    tag_host_ip = get_host_ip();

  # rDNS lookup
  if (defined_func("get_host_fqdn"))
  {
    rdns = get_kb_item("Flatline/get_host_fqdn");
    if (empty_or_null(rdns))
      rdns = get_host_fqdn();

    if (!empty_or_null(rdns))
    {
      tag_host_rdns = rdns;

      # add rdns data to FQDN tracking data structure
      found = FALSE;
      foreach ds_item (keys(ds))
      {
        if (ds[ds_item].FQDN == tag_host_rdns)
        {
          found = TRUE;
          append_element(var:ds[ds_item].sources, value:"get_host_fqdn()");
        }
      }
      if (!found)
      {
        add.FQDN = tag_host_rdns;
        add.sources = [ "get_host_fqdn()" ];
        append_element(var:ds, value:add);	
      }
    }
  } 

  # FQDN - use user-specified FQDN instead of rDNS lookup otherwise use rDNS
  var fqdn = determine_fqdn();
  if (!empty_or_null(fqdn))
  {
    tag_host_fqdn = fqdn;

    # add user-specified data to FQDN tracking data structure
    found = FALSE;
    foreach ds_item (keys(ds))
    {
      if (ds[ds_item].FQDN == fqdn)
      {
        found = TRUE;
        append_element(var:ds[ds_item].sources, value:"determine_fqdn()");
      }
    }
    if (!found)
    {
      add.FQDN = fqdn;
      add.sources = [ "determine_fqdn()" ];
      append_element(var:ds, value:add);	
    }
  }
}

if (!empty_or_null(ds))
  tag_host_fqdns = json_write(ds);


var report_tags =
[
  ['ssh-fingerprint',   "kb",     ["Host/OS/SSH/Fingerprint"]],
  ['mac-address',       "kb",     ["Host/mac_addrs"]],
  ['virtual-mac-address', "kb",     ["Host/virtual_mac_addrs"]],
  ['hostname',          "kb",     ["Host/hostname"]],
  ['host-fqdn',         "value",  tag_host_fqdn],
  ['host-fqdns',        "value",  tag_host_fqdns],
  ['host-rdns',         "value",  tag_host_rdns],
  ['host-ip',           "value",  tag_host_ip],
  # report_xml_tag called by scan_info.nasl, no kb item set
  #['Credentialed_Scan', "kb",     ""],
  ['smb-login-used',    "kb",     ["HostLevelChecks/smb_login"]],
  ['operating-system',  "kb",     ["Host/OS/" + best_meth]],
  ['operating-system-method',  "value", best_meth],
  ['operating-system-conf',    "value", string(best_score)]
];

var tag_value;
foreach var report_tag (report_tags)
{
  if (!get_kb_item("Host/Tags/report/" + report_tag[0]))
  {
    ## Retrieve tag value if it exists
    if (report_tag[1] == "kb")
    {
      foreach var tag_kb_item (report_tag[2])
      {
        tag_value = get_kb_item(tag_kb_item);
        if (strlen(tag_value))
          break;
      }
    }
    else if (report_tag[1] == "value")
    {
      tag_value = report_tag[2];
    }
    # Perform any manual processing required on specific tags here.
    if (report_tag[0] == "operating-system")
    {
      # At least for now, replace the legacy macOS formatting with the current expected format
      # All sw_vers response appear as Mac OS X for 10.* and macOS for 11.* onward.
      # Consult RES-101983 for further details.
      if (preg(pattern:"^Mac OS X ", string:tag_value))
      {
        if (!preg(pattern:"^Mac OS X 10\.", string:tag_value))
        {
          tag_value = ereg_replace(string:tag_value, pattern:"^Mac OS X ", replace:"macOS ");
        }
        # KB for flatline testing purposes
        replace_kb_item(name:"Flatline/MacOSX/operating-system/os_fingerprint2", value:tag_value);
      }
    }

    ## Set Host/Tags/report/* value
    if (strlen(tag_value))
    {
      replace_kb_item(name: "Host/Tags/report/" + report_tag[0], value: tag_value);
      report_xml_tag(tag:report_tag[0], value:tag_value);
    }
  }
}

## Set additional tags not in dashboard_report_host_get_tags
var os_full = get_kb_item("Host/OS/" + best_meth);
var tag_os = 'other';
var tag_vendor = '';
var tag_product = '';
var tag_cpe = '';
var os_linux, os_windows, os_mac, kb_exists, kb_val_match;
if (strlen(os_full) && preg(pattern:"windows|microsoft", string: os_full, icase:TRUE)) {
  tag_os = 'windows';
  tag_vendor = 'microsoft';
  tag_product = 'windows';
  tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
}
else if (strlen(os_full) && preg(pattern:"linux|unix", string: os_full, icase:TRUE)) {
  tag_os = 'linux';
  tag_vendor = 'linux';
  tag_product = 'linux_kernel';
  tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
}
else if (strlen(os_full) && preg(pattern: "apple|mac|os_x|osx|os x|iphone|ipad", string: os_full, icase: TRUE)) {
  tag_os = 'mac';
  tag_vendor = 'apple';
  tag_product = '';
  tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
}
else
{
  # Generic OS + CPE Vendor/Product pairs
  # os_*[0]         os_*[1], os_*[2]
  os_linux =    ["linux",   "linux",      "linux_kernel"];
  os_windows =  ["windows", "microsoft",  "windows"];
  os_mac =      ["mac",     "apple",      "mac_os"];
  #os_mac_osx = ["mac", "apple", "mac_os_x"];
  #os_mac_server = ["mac", "apple", "mac_os_server"];
  #os_mac_x_server = ["mac", "apple", "mac_os_x_server"];
  #os_iphone = ["mac", "apple", "iphone_os"];

  kb_exists = [
    [os_linux, "Host/Linux/Distribution"]
  ];
  kb_val_match = [
    [os_linux, "LINUX", "mDNS/os"],
    [os_linux, "Linux", "Host/OS/uname"],
    [os_linux, "Archos70", "upnp/modelName"],
    [os_linux, "linux|solaris", "Services/data_protector/patch_info_is_str"],
    [os_linux, "linux|unix|Sun SNMP|hp-ux|hpux", "SNMP/sysName"],
    [os_linux, "openBSD|linux|unix|netbsd|aix|hp-ux|sco_sv", "Host/OS/ntp"],
    [os_linux, "linux|unix|Nexus [0-9]+[a-zA-Z]* Switch|Data Domain OS", "SSH/textbanner/*"],
    [os_linux, "linux|unix|netbsd|openbsd|freebsd|minix|sunos|aix|irix|dragonfly", "Host/uname"],
    [os_linux, "linux|unix|sun_ssh|freebsd|netbsd|ubuntu|debian|cisco|force10networks", "SSH/banner/*"],
    [os_linux, "linux|unix|iris|aix|minix|netbsd|openbsd|freebsd|Dell Force10|cisco|Silver Peak Systems|HP-UX|hpux", "SNMP/sysDesc"],

    [os_windows, "Service Pack ", "SMB/CSDVersion"],
    [os_windows, "Windows", "Host/OS/smb"],
    [os_windows, "Windows", "Host/Veritas/BackupExecAgent/OS_Version"],
    [os_windows, "Windows ", "SMB/ProductName"],
    [os_windows, "Windows ", "upnp/modelName"],
    [os_windows, "microsoft", "Services/data_protector/patch_info_is_str"],
    [os_windows, "microsoft|windows", "SNMP/sysName"],
    [os_windows, "microsoft|windows", "Host/OS/ntp"],

    [os_mac, "AFP[X23]", "Host/OS/AFP/fingerprint"],
    [os_mac, "apple|darwin", "SNMP/sysDesc"],
    [os_mac, "darwin", "Host/uname"],
    [os_mac, "Mac OS X", "mDNS/os"],
    [os_mac, "cygwin|mingw32", "Host/uname"],
    [os_mac, "Darwin Kernel Release", "SNMP/sysName"],
    [os_mac, "(Darwin).*(x86_64|i386)", "Host/OS/ntp"]
  ];

  var kblist, os_info, kbval, addl_tags;
  foreach var kbitem (kb_exists)
  {
    if (get_kb_item(kbitem[1]))
    {
      os_info = kbitem[0];
      tag_os = os_info[0];
      tag_vendor = os_info[1];
      tag_product = os_info[2];
      tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
      break;
    }
  }

  foreach kbitem (kb_val_match)
  {
    if (tag_cpe != '') break;
    kblist = get_kb_list(kbitem[2]);
    foreach var kbkey (keys(kblist))
    {
      kbval = kblist[kbkey];
      if (preg(pattern: kbitem[1], string: kbval, icase: TRUE))
      {
        os_info = kbitem[0];
        tag_os = os_info[0];
        tag_vendor = os_info[1];
        tag_product = os_info[2];
        tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
        break;
      }
    }
  }
}

addl_tags =
[
  ['os',            "value",  tag_os],
  ['cpe',           "value",  tag_cpe]
  #['id',            "value",  ""],
  #['is_new',        "value",  ""],
  #['is_auth',       "value",  ""],
  #['scan_type',     "value",  ""],
  #['severity',      "value",  ""],
  #['severitycount', "value",  ""],
  #['last_update',   "value",  ""],
  #['host_index',    "value",  ""]
];

foreach var addl_tag (addl_tags)
{
  if (!get_kb_item("Host/Tags/report/" + addl_tag[0]))
  {
    ## Retrieve tag value if it exists
    if (addl_tag[1] == "kb")
    {
      foreach tag_kb_item (addl_tag[2])
      {
        tag_value = get_kb_item(tag_kb_item);
        if (strlen(tag_value))
          break;
      }
    }
    else if (addl_tag[1] == "value")
    {
      tag_value = addl_tag[2];
    }

    ## Set Host/Tags/report/* value
    if (strlen(tag_value))
    {
      set_kb_item(name: "Host/Tags/" + addl_tag[0], value: tag_value);
      report_xml_tag(tag:addl_tag[0], value:tag_value);
    }
  }
}

function build_cpe_from_tags(type, vendor, product)
{
  local_var cpe_string;
  cpe_string = 'cpe:/';
  if (type != '')
  {
    cpe_string += type;
    if (vendor != '')
    {
      cpe_string += ':'+vendor;
      if (product != '')
      {
        cpe_string += ':'+product;
      }
    }
  }
  return cpe_string;
}
