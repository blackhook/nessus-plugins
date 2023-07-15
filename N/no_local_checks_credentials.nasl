#TRUSTED 15753b01f129d358650a71da11e9bac5269dedc1848c062af998e224274053d6f7f3c73a60ae03b92e239683c5a954737e7861f0af4fe68b11304a1195d2f743175a53020f259845c15ef2d44e235b60da300baffb0ca01f21d3132b162f38a3351f9d3695a4a689b091076f4cf8345635e0dce7d44c51fc952a3fabbe4db73410c7bbee5b466b14fd9e7f7fdb013d1b647ed72baf4bfd7149c751eb68507d669e6211cd7c0783ca27cea538d75a91aec68576874347857867fb58c19aa1247c7676ca029ec1ca4cdced88a8ccf629be47c60b073e1736fc7a9b3b3025e9fa7e773d4e6e81d16f68e7a5416adf0ae9baf116cfe8f1b674d6f430f53546040e5b7371eb72326bce8063e97b6eb0f305367132f2f7cdb34fad6e4219606921aec2fa8e0b4034662ab8cc8943c490f26876e2de4a2eb67fc24c8bcb003a95f9ed90f13c05d90337dd46bde52dddc9880bda17708d3f0f0e7cf3e308afe62aac333764e2b0bb6c79ab43e0e67a021c279fad0df16bd49f7de97af5be7bcf349ddf8cfd02b6d79e205548d0949bd615dc0c24d932fd963b2a65f2975bc7c681bea77324ff4afcd86197c84f3a0fd939d56b91d8b658798eda2a7dd803ad20d116d5f71ba3d40fdee9b35efc2d34b884af842de1fe44be03564c617614a30420de766ee6df1f43d451599e1e36dbe9ab3c9a98d00cbd7db1f3bc9e2451b0d09c7fb034
#TRUST-RSA-SHA256 998c2773af769f23607754bf0528d75722e233be5e33daed5bc986eb249c7be00a3f51bdce3cb1b5c5d287637c6b620718ba19fd7dc95bb25bfe2fb48d2d6766fae562c3f91034e8788ae488082b64e15d28472ba16251560cbc6305903a3ca70288868a74d1794849d8ad1aa9ff7c1b4fcc892831b385cfd72630f557be821ccf29bacd4456daa556c51d1b6fd1e2c44fc11e5435092ccc00e0c18e9dae3794bed83ba4997ff66fb3703467c334e5f486d58a9232a5816e8a253b51f9d037479487f702e7c1411ed5dd8f3ab8c4554ce7e331fe28525a7a95766daa417cd68a6e0beace00f1d6bf99b63f1949bfa901a090e6c1daa08b959eaffb303caf601067e36632ca9b43e410a4312891504d5a3ce2aeca8780205be1415f0f3d3dcc439304023eb26501b50c5b2efd992b88d27c5b2b6ff73abee8abe131802ca0367255d919015ba04160183a0c1b4670054689d237fa11f19f35d5c32cb40f4a80fc3abac8be0de8974a83f1ce519d4b6093fa8826fa5dd24f1d417d6ae0172148a280bd512011e248ace26d4b2f94c4a188baf734fb09366af4ad4d8fc0b62715fa6b2a933b1e83dc790c56224fe14277df4e52ba0651fd059ca13c4a671325aea815985bf6c1ca8e0f45ef3a9b94d886e1d509221eaa9533ab2b45221a1b15e83b4ef248a83d70082da6ce76912ea301360f6461778723ee296f52d51ac3fb3c12
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110723);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/13");

  script_xref(name:"IAVB", value:"0001-B-0504");

  script_name(english:"Target Credential Status by Authentication Protocol - No Credentials Provided");
  script_summary(english:"Reports protocols that have no credentials provided in the scan policy.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to find common ports used for local checks,
however, no credentials were provided in the scan policy.");
  script_set_attribute(attribute:"description", value:
"Nessus was not able to successfully authenticate directly to the
remote target on an available authentication protocol. Nessus was
able to connect to the remote port and identify that the service
running on the port supports an authentication protocol, but Nessus
failed to authenticate to the remote service using the provided
credentials. There may have been a protocol failure that prevented
authentication from being attempted or all of the provided credentials
for the authentication protocol may be invalid. See plugin output for
error details.

Please note the following :

- This plugin reports per protocol, so it is possible for
  valid credentials to be provided for one protocol and not
  another. For example, authentication may succeed via SSH
  but fail via SMB, while no credentials were provided for
  an available SNMP service.

- Providing valid credentials for all available
  authentication protocols may improve scan coverage, but
  the value of successful authentication for a given
  protocol may vary from target to target depending upon
  what data (if any) is gathered from the target via that
  protocol. For example, successful authentication via SSH
  is more valuable for Linux targets than for Windows
  targets, and likewise successful authentication via SMB
  is more valuable for Windows targets than for Linux
  targets.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("lcx.inc");

global_var report = '';
global_var creds_found = FALSE;

if(get_kb_item('Host/local_checks_enabled'))
  exit(0, 'Local checks have been enabled on the host.');

function check_ssh()
{
  var ssh, ssh_ports_string, plural, ssh_cred, ssh_cred_list, os, ssh_sudo;
  os = get_kb_item('Host/OS');
  # Don't report if os is windows or we aren't paranoid and don't know the OS 
  if((report_paranoia < 2 && !os) || "Windows" >< os)
    return NULL;
  ssh = get_service_port_list(svc:'ssh');
  if(ssh && max_index(ssh) > 0)
  {
    ssh_ports_string = '';
    if(max_index(ssh) > 1)
    {
      plural = 's';
      ssh_ports_string = join(ssh, sep:', ');
    }
    else
    {
      plural = '';
      ssh_ports_string += ssh[0];
    }
    # remove leading space and trailing comma
    ssh_cred = get_kb_item("Secret/SSH/login");
    ssh_sudo = get_kb_item("Secret/SSH/sudo_method");
    ssh_cred_list = get_kb_list('Secret/SSH/*/login');


    # When no SSH credentials are provided root may be the default login and all sudo options may be set
    if ((empty_or_null(ssh_cred) || ssh_cred == "root") &&
        (empty_or_null(ssh_sudo) || ssh_sudo == "Nothing;sudo;su;su+sudo;dzdo;pbrun;Cisco 'enable'") &&
        !ssh_cred_list)
    {
      report += 'SSH was detected on port'+plural+' '+ssh_ports_string+' but no credentials were' +
        ' provided.\nSSH local checks were not enabled.\n\n';

      lcx::log_issue(type:lcx::ISSUES_INFO, msg:
        "Credentials were not provided for detected SSH service.");
    }
    else
      creds_found = TRUE;
  }

}

function check_smb()
{
  var smb, smb_ports_string, plural, smb_cred_list, os, credential_repos, auth_methods, auth_methods_used;
  os = get_kb_item('Host/OS');
  # Don't report if os is not windows or we aren't paranoid and don't know the OS
  if((report_paranoia < 2 && !os) || "Windows" >!< os)
    return NULL;
  smb = get_kb_list('SMB/transport');
  
  # remove leading space and trailing comma
  if(smb && max_index(keys(smb)) > 0)
  {
    smb_ports_string = '';
    if(max_index(keys(smb)) > 1)
    {
      plural = 's';
      smb_ports_string = join(smb, sep:', ');
    }
    else
    {
      plural = '';
      smb_ports_string += smb['SMB/transport'];
    }
 
    # SMB/login_filled means credential using "Password" auth methods
    # target/auth/method for all other auth methods
    smb_cred_list = get_kb_list("SMB/login_filled/*");
    auth_methods = make_list(get_kb_list("target/auth/method"));
    credential_repos = make_list(
      'Thycotic', 
      'BeyondTrust', 
      'Centrify', 
      'Lieberman', 
      'HashiCorp', 
      'Arcon', 
      'CyberArk', 
      'CyberArk REST', 
      'LM Hash', 
      'NTLM Hash');
    auth_methods_used = collib::intersection(credential_repos, auth_methods);
 
    if (empty_or_null(smb_cred_list) && empty_or_null(auth_methods_used))
    {
      report += 'SMB was detected on port'+plural+' '+smb_ports_string+' but no credentials were' +
        ' provided.\nSMB local checks were not enabled.\n\n';
      lcx::log_issue(type:lcx::ISSUES_INFO, msg:
        "Credentials were not provided for detected SMB service.");
    }
    else
      creds_found = TRUE;
  }

}

function check_snmp()
{
  var snmp, snmp_ports_string, plural, snmpv3_user, snmp_comm_names, os, snmp_default_port;
  os = get_kb_item('Host/OS');
  # Don't report if os is not windows or we aren't paranoid and don't know the OS
  #if((report_paranoia < 2 && !os) || os >!< "Windows")
  #  return NULL;
  snmp = get_service_port_list(svc:'snmp');
  snmpv3_user = get_kb_item("SNMP/v3/username");
  snmp_comm_names = get_kb_list("SNMP/community_name/*"); # < v3
  snmp_default_port = get_kb_item('Ports/udp/161');
  plural = '';
  if(!snmp && !snmp_default_port)
    return NULL;
  if(max_index(snmp) > 1)
  {
    plural = 's';
    snmp_ports_string = join(snmp, sep:', ');
  }
  else if(!snmp)
    snmp_ports_string = '161';
  if (
      max_index(keys(snmp_comm_names)) == 1 &&
      snmp_comm_names['SNMP/community_name/0'] == 'public' &&
      get_kb_item('SNMP/auth_failed') && 
      !snmpv3_user
    )
  {
    report += 'SNMP was detected on port'+plural+' '+snmp_ports_string+' but no credentials were' +
      ' provided.\nSNMP local checks were not enabled.\n\n';
      lcx::log_issue(type:lcx::ISSUES_INFO, msg:
        "Credentials were not provided for detected SNMP service.");
  }
    else
      creds_found = TRUE;

}

function check_panweb()
{
  if (!get_kb_item("www/panweb")) return NULL;
  if (get_kb_item("Secret/Palo_Alto/Firewall/Login"))
  {
    creds_found = TRUE;
    return NULL;
  }
  var port_str = "";
  var kbs = get_kb_list("www/*/palo_alto_panos");
  if (!isnull(kbs))
  {
    kbs = keys(kbs);
    var s = "";
    if (max_index(kbs) > 1) s = "s";
    port_str = " on port" + s + " ";
    var ports = [];
    foreach var kb (kbs)
    {
      kb -= "www/";
      kb -= "/palo_alto_panos";
      ports[max_index(ports)] = kb;
    }
    port_str += join(ports, sep:', ');
  }

  report +=
    'Palo Alto Networks PAN-OS Web UI was detected' + port_str +
    ' but\nno credentials were provided.' +
    '\nPAN-OS local checks were not enabled.\n\n';

  lcx::log_issue(type:lcx::ISSUES_INFO, msg:
    "Credentials were not provided for detected PAN-OS WebUI service.");

  return NULL;
}

#function check_vsphere()
#{
#  var kbs = get_kb_list("Host/VMware/vsphere");
#  if (isnull(kbs)) return NULL;
#
#  # Check for an open vsphere port that supports HTTPS
#  var encaps, ports = [];
#  foreach var p (make_list(kbs))
#  {
#    if (!get_port_state(p)) continue;
#    encaps = get_kb_item("Transports/TCP/"+p);
#    if (encaps == ENCAPS_IP) continue;
#    ports[max_index(ports)] = p;
#  }
#  if (max_index(ports) < 1) return NULL;
#
#  if (get_kb_item("Secret/VMware/login"))
#  {
#    creds_found = TRUE;
#    return NULL;
#  }
#
#  var a = "A";
#  var s = "";
#  var was = " was";
#  if (max_index(ports) > 1)
#  {
#    a = "";
#    s = "s";
#    was = " were";
#  }
#  ports = " " + join(make_list(ports), sep:', ');
#
#  report +=
#    a+' VMware ESX/ESXi SOAP API webserver'+s+was+' detected on port'+s + ports +
#    '\nbut no credentials were provided.' +
#    '\nESX/ESXi local checks were not enabled.\n\n';
#  lcx::log_issue(type:lcx::ISSUES_INFO, msg:
#    "Credentials were not provided for detected ESX/ESXi SOAP API.");
#
#  return NULL;
#}

#function check_vcenter()
#{
#  if (get_kb_item("Host/VMWare/found"))
#  {
#    if (empty_or_null(get_kb_item("Host/VMware/esxcli_software_vibs")) && empty_or_null(get_kb_item("Host/VMware/esxupdate")))
#    {
#      report +=
#        'VCenter detected this ESX/ESXi host but did not return patch details.' +
#        '\nWithout these details vulnerability data may be missing or inaccurate' +
#        '\nCheck your VCenter server for connectivity or licensing issues\n\n';
#      lcx::log_issue(type:lcx::ISSUES_INFO, msg:
#        "VIBS were not provided for detected ESX/ESXi Host.");
#    }
#  }
#  return NULL;
#}

check_ssh();
check_smb();
check_snmp();
check_panweb();
# Disabling these because the check is not correct - jhammack
# It is triggering vCenter as ESXi and saying no creds/etc
#check_vsphere();
#check_vcenter();

if(strlen(report) > 0)
  security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
else if(creds_found)
{
  if (get_kb_list("Host/Auth/*/Failure") && !get_kb_list("Host/Auth/*/Success"))
    exit(0, 'Services supporting local checks were found, but credentials failed.');
  else exit(0, 'Services supporting local checks were found, but local checks were not enabled.');
}
else
  exit(0, 'No services supporting local checks were found on the host.');
