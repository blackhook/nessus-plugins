#TRUSTED 56af5c37c9a5dc3c03c8cab7fc269e514857bd065153650df54a5150294db4138a32fd28ea008fe6965ec1e874cc4d7f355d925f49d5fce7353729f7ed589f7dfdccc27e711763732adf8ff195eac1727d767412f6a103411507dd62958b413c8eece4034b8a8e64ffe6c7282a50e80ea5a3c8bdfb358bb2bd7db5c40921e443b5fa868a68cb383e084df3fb508b2e6352bcf11b2c6f537bdb345885babd214314655b82b91d6d9cd34c2e9b4176a7f0e98635ce07f894395e5d52c0e2d755c46fcdc6567279cb2ed4decc8b754236eff862f735b7976085a2ece0714c7c86e0f9ac70c3c7078793eed83e9c37cc97ae451fcb776d61b9a4c568732687ce5cae47082c59b103088ca62d7dce429af8553d80eb0bd06cf62bf2c1f2568345f7074e6b57c763b11edcdd08fd694751a542e86c28c690115d100b6faadd1141112c58c325f7b7d008211f69b55bbea57019483c006397d9650a82e23cae589a6e39b4a7631e8059711a3f036643e2a0fa10b6fdef9839e19439211bbbc66f9dfb8ce6b38b649da9218705afdbc517341e169bb69fd2100be96b46ab7438e455a19276ff889a77809734fccd3e4fbfa94627ff064c52fca2807e1a393138ecea277a8421a0d3343fa7265e948c995e3a9c5afec13c20f1a326bcb18401d757f3e5e60ac00053c9b4f54dfdb3a9cf952c901f29cc76c9a5b5e41fdc4fef3d68e81a22
#TRUST-RSA-SHA256 a2f0d92a227889c9a9f11e4de3cce1dc67bc855158b35e9591ad6d7a630bc429dde6dd201238f9448da54085586504dfe506e173e0b212fc2244a98a345fba815310caeef1e01e62486b68954a2fa4a015a4defa6b77902d239b752789dbc4557575cfbd0f3b801f4d279318c6b8355214188e5a2b024d451435c2b9de8ed6a91f8797768f7fcc4d1729a7b9df542301246527d2f36fb73cb67832bca1d1ec6f3946fec550266d0ada9e5cf5b508013cb928df5251809dd1e127346341b2ebca37f38babe5824f79f942dc37eb1c5cb7447730ff5a9f78b3f6394f05b36bf564a04d860bf2f29fd108e75bdfbb390715ff2db030eff1859d8d11a99336664d47a7dd4042f3656b8f8e650570c543b270e57cfe04013c35beff7a9d284da1bde6bd5be45cbb42c449780b3d9945a88d08b896a376f7158f1a236221495f740ac5933ecb5dc95ff67678687ba2a134a7d55a84ecbfc66d90a67bcd8880ebffbe6a2b111131d5d7e183ae29a63ed46c173b6d9923169b18998f4601021c4d4450d19e8e7f5ac586b9b94f4e63ea4c9bc3ab847c5f8286b93f143759ba231a3459c4daf92c2ff03cc80185ff1b3c2b4d357b7e1da0c22aa6f83612deb63e7b243c8b36df8d15483c3afd2cde40fbc14eaa1f1d40b3c1e3d0da16fe2dbadf8921ca7ca679ce63e6decfb557a8481b77c0965bf66cdeb9498001e1adc31b152d374e09
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108798);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_name(english:"SSH Multiple Device Default Credentials (PCI)");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a known set of credentials.");
  script_set_attribute(attribute:"description", value:
"The remote device is a device that uses a set of publicly known, default
credentials. Knowing these, an attacker able to connect to the service
can gain control of the device.

WARNING: This plugin may run up to 4 hours depending on network conditions.");
  script_set_attribute(attribute:"see_also", value:"https://www.urtech.ca/2011/12/default-passwords/");
  script_set_attribute(attribute:"solution", value:
"Log into the remote host and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"default credentials");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "account_check.nasl", "ssh_detect.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Settings/PCI_DSS_local_checks", "global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);
  script_timeout(15000);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("pci_password_dict.inc");
include("ssh_bruteforce.inc");
include("lists.inc");
include("spad_log_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

if (get_kb_item("Settings/PCI_DSS_local_checks"))
  exit(1, "This plugin only runs for PCI External scans.");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

logins = get_pci_login_list();
debug = get_kb_item("global_settings/enable_plugin_debugging");

function passlist_of_user(logins, user)
{
  var passlist = [];
  var login;
  foreach login (logins) 
  {
    if (login['username'] == user)
      collib::push(login['password'], list:passlist);
  }
  return passlist;
}

sshlib::KEX_SUPPORTED_NAME_LISTS["kex_algorithms"] +=
  ",diffie-hellman-group1-sha1";

ssh_ports = get_service_port_list(svc: "ssh", default:22);
starttime = unixtime();
children_pid = make_list();
fork_count = 0;

ssh_obj = NULL;
foreach ssh_port (ssh_ports)
{
  if (!isnull(ssh_obj)) delete(ssh_obj);
  ssh_obj = new("bruteforce_pci");
  if (!get_port_state(ssh_port))
  {
    if(debug)
      spad_log(message:'Port "'+ssh_port+'" is unavailable.');
    continue;
  }
  foreach login (logins)
  {
    var user = login['username'];
    var passlist = passlist_of_user(logins:logins, user:user);
    var pid = fork_ex(options:SHARED_OBJECTS);
    children_pid[fork_count] = pid;
    fork_count += 1;

    if ( pid == 0 )
    {
      var res = check_username(username:user, port:ssh_port, passlist:passlist);
    }

    if (ssh_obj.affected && !thorough_tests) break;
  }
  foreach waitpid (children_pid)
  {
    wait(pid:waitpid);
  }
  
  if (ssh_obj.affected && ssh_obj.report)
  {
    report =
      '\nNessus was able to gain access using the following credentials :' +
      '\n' + ssh_obj.report;
    security_report_v4(port:ssh_port, severity:SECURITY_HOLE, extra:report);
  }
  else if (ssh_obj.server_failed)
  {
    exit(0, "The remote host is dropping authentication attempts. " + ssh_obj.server_failures + " of " + (ssh_obj.server_failures+ssh_obj.auth_failures) + " attempts were dropped by the server. An IPS may be affecting network conditions such that a brute force attempt is infeasible.");
  }
  else if (ssh_obj.scan_timeout)
  {
    exit(0, "Network conditions caused the scan time to exceed 4 hours (" + ((max_index(ssh_obj.server_failures)+max_index(ssh_obj.auth_failures)) / 100) + "% complete). Discontinuing brute force attempt due to network interference.");
  }
}

if(!ssh_obj.affected) audit(AUDIT_HOST_NOT, "affected");
