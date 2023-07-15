#TRUSTED 76b84d5ae937b831456d9432c0329147822520cacd681c0282147fe35df446785002461955dce06436221d4be1d140d98941a3fd5cd16459044fd6126db0b2c6764f0e6bdf0670371e53f3e91b30b94870af45252303e1ff7aa805d8927c9b4078337e68f610dcea0b391c3dd2a6887a332d17446f77bc58286d74afcca0681e52fb647ecf9abcdc9316a0423a1d5f14ce52cd8a3177cf90dea36b90c62a56b27c4a9cdfb74f45e89952e764365ad3773c394d1036e31a56c9c028c39a8c7a7e9005bf086fce722370c7e70e1277539e6852ca8b6e67b55b2533bf8a7c3b29dc9696dcd3af83cbf45ca209dbfff8f3ac5af1253f7e7cb3f8e170c17c13e9286efd617a45a54707359ddb14c3d93c43aa4500889f143c1898ac216f7d57ef007239eeb90037c22c3fdfaa63574b64441e37875f4ce38e32b3c72a20fc250b72844eec7110c41387516a6cddc712ce3e7748063c3c7b3e1bbbc5dee05e87af96bb576698f1109838b146a3496286c7961c9ab7b0474ae543323c975543399e4086228d54d72d136e78c85c106c62b56e5cc444ec7ef0022a27748ea4a65fe99fb4d192ba67e5aca4bc39d51ff38a7f314dbdc9f10a9645e7d79fd816c0835650ca1b6292c6e6eed5a2a71187767e6c0434c4528393234c929eaeb77cd744bfd8d3874e737b5e527a84bcea8e7fb4bf43516659d7420c16a326ab3d3740be09fee2
#TRUST-RSA-SHA256 4c1d0ad36d4cfa4ad01b19d31701472f34e3bbdc4ebaa4c0d208dd40e422e057bd3bf2e559672977bf0473960bd45742a56fb5a7eeabaa19b0de1cc1352d0f90d3c2218c181477d4cb7304950ef62be558e0d837b6a2226d215291a611383e19407d6ebe55db5f398d73406d9bcd30c3916d53b32e4fecf3c7f3990ec706f12b3cccb0df92fe2ac3ebfa92de60622160980d31ae5f92ec4e8cc171d6199f0cbb02780933530e5eda9a975b2b010714507c05b80001daaa9afcd7f5907aca383e43ab8514ef2a3d75432e21688d2487f387b4f301070a35f065835032cdd40c881407b549f72a2215167b351fc37efaa8dac05273ba959974bcfc2b99887f260ff885dc3e2b19d349ce317926c0ff33a0be7acb12c9457e3ca0b3dea5645badf5dba6adde6c9100f8586f28e0f325b2769d9a0c37803e997e8b6de58093af6ca07986e50af5bc305901927b5d8508c1efda7b9a6c406172b4f9b6aa61532943b0e974a3d2dff225af3a0e2336462a86271d194d9fcd10803f5b08d29fa74c9bf515d87ceeb10b98dd9e68123929d14b1fd913c00d204a5a16b9bc43a4cddb5cf2268688b9e9bdaac232737d97090dcf3550218bcb80ac84a04803ada9f723b919dfaa1a259df43c522c224246c765ebdec59d57c69a2cecf962a6beffbf912f2e227ce4d2da8a114ba72c12b44e4cd99a8243d6f96700e8343bde0c1457ad4750
#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(166602);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/27");

  script_name(english:"Asset Attribute: Fully Qualified Domain Name (FQDN)");

  script_set_attribute(attribute:"synopsis", value:
"Report Fully Qualified Domain Name (FQDN) for the remote host.");
  script_set_attribute(attribute:"description", value:
"Report Fully Qualified Domain Name (FQDN) for the remote host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"all");

  script_end_attributes();

  script_category(ACT_END);
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("fqdn.nasl", "netbios_name_get.nasl", "microsoft_windows_nbt_info.nbin", "smb_nativelanman.nasl", "wmi_system_hostname.nbin");

  exit(0);
}

include('resolv_func.inc');
include('lists.inc');
include('agent.inc');


# build list of methods that generate the same FQDN
function build_method_list(method_list)
{
  var m, r;

  if ( isnull(method_list) || !is_list(method_list) )
    return NULL;

  if ( len(method_list) > 1 )
  {
    r = '\n  Methods    :';
    foreach m (method_list)
      r += '\n    - ' + m;
  }
  else
  {
    r = '\n  Method     : ' + method_list[0];
  }

  return r;
}


# build list of FQDN from various upstream plugins
function build_fqdn_list(fqdn, method, &fqdns)
{
  var f = tolower(fqdn);

  if (contains_element(var:keys(fqdns), value:f))
    append_element(var:fqdns[f], value:method);
  else
    fqdns[f] = [method];
}

# validate and remove invalid FQDN from FQDN list
function validate_fqdn(&fqdns)
{
  var fqdn_list = keys(fqdns);
  var invalid_fqdn = [];

  for (var i=0; i<len(fqdn_list); i++)
  {
    for (var j=0; j<len(fqdn_list); j++)
    {
      if (
          !valid_fqdn(fqdn:fqdn_list[i]) || 
          fqdn_list[i] =~ "\.workgroup$" || 
          ( fqdn_list[i] >< fqdn_list[j] && fqdn_list[i] != fqdn_list[j] )
        )
        append_element(var:invalid_fqdn, value:fqdn_list[i]);
    }
  }

  # delete invalid FQDN from FQDN list
  foreach i (collib::remove_duplicates(invalid_fqdn))
    delete_element(var:fqdns, idx:i);
}


function build_report(fqdn, confidence, resolves, &fqdns)
{
  return strcat(
    '\n  FQDN       : ', fqdn,
    '\n  Confidence : ', confidence,
    '\n  Resolves   : ', resolves,
    build_method_list(method_list:fqdns[fqdn])
  );
}



###
#  Main
###

var report = 'The FQDN for the remote host has been determined to be:\n';
var extra_report = '\n\nAnother possible FQDN was also detected:\n';
var fqdns = {}, fqdn, r, f, resolved_fqdns = [], non_resolved_fqdns = [];

# fqdn.nasl
if (get_kb_item('FQDN/Succeeded'))
{
  var fqdn = get_kb_item('Host/FQDN');
  build_fqdn_list(fqdns:fqdns, fqdn:fqdn, method:'rDNS Lookup: IP Address');
}

# microsoft_windows_nbt_info.nbin
var smb_name = get_kb_item('SMB/name');
var domain = get_kb_item('SMB/primary_domain');
if ( !empty_or_null(smb_name) && !empty_or_null(domain) )
  build_fqdn_list(fqdns:fqdns, fqdn:strcat(smb_name, '.', domain), method:'NetBIOS: remote query');

# wmi_system_hostname.nbin
var wmi_host_name = get_kb_item('Host/hostname');
var wmi_domain = get_kb_item('Host/WMI/Domain');
if ( !empty_or_null(wmi_host_name) && !empty_or_null(wmi_domain) )
  build_fqdn_list(fqdns:fqdns, fqdn:strcat(wmi_host_name, '.', wmi_domain), method:'WMI: Win32_ComputerSystem class');

# smb_hotfixes.nasl
var reg_host_name = get_kb_item('SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ComputerName/ComputerName/ComputerName');
var reg_domain = get_kb_item('SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain');
if ( !empty_or_null(reg_host_name) && !empty_or_null(reg_domain) )
  build_fqdn_list(fqdns:fqdns, fqdn:strcat(reg_host_name, '.', reg_domain), method:'Registry: ComputerName + Domain');

# smb_nativelanman.nasl
var port = get_kb_item("SMB/transport");
if (empty_or_null(port)) port = 445;
var ntlm_fqdn = get_kb_item(strcat('SMB/', port, '/NTLM/dns_computer_name'));
if ( !empty_or_null(ntlm_fqdn) )
  build_fqdn_list(fqdns:fqdns, fqdn:ntlm_fqdn, method:'SMB: NTLMSSP');

if (empty_or_null(fqdns))
  exit(1, 'Failed to collect FQDN info for the remote host.');

validate_fqdn(fqdns:fqdns);

if (empty_or_null(fqdns))
  exit(1, 'No valid FQDN is found for the remote host. Exiting...');


# only attempt FQDN resolution in non-agent scan
if (!agent())
{
  foreach f (keys(fqdns))
  {
    r = fqdn_resolv(name:f, ipv6:FALSE, fqdn:TRUE);
    if (!empty_or_null(r))
      append_element(var:resolved_fqdns, value:f);
    else
      append_element(var:non_resolved_fqdns, value:f);
  }
}
else
{
  non_resolved_fqdns = keys(fqdns);
}

if (!empty_or_null(resolved_fqdns))
  foreach f (resolved_fqdns)
    report += build_report(fqdn:f, confidence:100, resolves:'True', fqdns:fqdns);

if (!empty_or_null(non_resolved_fqdns))
{
  foreach f (non_resolved_fqdns)
  {
    if ( empty_or_null(resolved_fqdns) )
      report += build_report(fqdn:f, confidence:60, resolves:'False', fqdns:fqdns);
    else
      extra_report += build_report(fqdn:f, confidence:60, resolves:'False', fqdns:fqdns);
  }
}

if (!empty_or_null(resolved_fqdns))
  report += extra_report;

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
