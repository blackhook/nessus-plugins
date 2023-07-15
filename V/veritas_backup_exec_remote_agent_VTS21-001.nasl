##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146990);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/08");

  script_cve_id("CVE-2021-27876", "CVE-2021-27877", "CVE-2021-27878");
  script_xref(name:"IAVA", value:"2021-A-0115");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/28");

  script_name(english:"Veritas Backup Exec Remote Agent 16.x < 21.2 Multiple Vulnerabilities (VTS21-001)");

  script_set_attribute(attribute:"synopsis", value:
"A remote data protection agent installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Veritas Backup Exec Remote Agent installed on the remote Windows host is 16.x prior to 21.2. It is,
therefore, affected by multiple vulnerabilities, as follows:

- An issue was discovered in Veritas Backup Exec before 21.2. The communication between a client and an Agent
  requires successful authentication, which is typically completed over a secure TLS communication. However,
  due to a vulnerability in the SHA Authentication scheme, an attacker is able to gain unauthorized access and
  complete the authentication process. Subsequently, the client can execute data management protocol commands
  on the authenticated connection. By using crafted input parameters in one of these commands, an attacker can
  access an arbitrary file on the system using System privileges. (CVE-2021-27876)

- An issue was discovered in Veritas Backup Exec before 21.2. It supports multiple authentication schemes: SHA
  authentication is one of these. This authentication scheme is no longer used in current versions of the
  product, but hadn't yet been disabled. An attacker could remotely exploit this scheme to gain unauthorized
  access to an Agent and execute privileged commands. (CVE-2021-27877)

- An issue was discovered in Veritas Backup Exec before 21.2. The communication between a client and an Agent
  requires successful authentication, which is typically completed over a secure TLS communication. However,
  due to a vulnerability in the SHA Authentication scheme, an attacker is able to gain unauthorized access and
  complete the authentication process. Subsequently, the client can execute data management protocol commands
  on the authenticated connection. The attacker could use one of these commands to execute an arbitrary
  command on the system using system privileges. (CVE-2021-27878)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS21-001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas Backup Exec Remote Agent version 21.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27878");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-27877");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Veritas Backup Exec Agent Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:backup_exec_remote_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is This script is Copyright (C) 2021-2023 21 Tenable Network Security, Inc.");

  script_dependencies("veritas_backup_exec_remote_agent_installed.nbin");
  script_require_keys("installed_sw/Veritas Backup Exec Remote Agent", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Veritas Backup Exec Remote Agent', win_local:TRUE);

var dbaid_key = 'Software\\Veritas\\Backup Exec For Windows\\Backup Exec\\Engine\\Agents\\XBSA\\Machine\\DBAID';

registry_init(full_access_check:FALSE);
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:FALSE);
var dbaid_key_val = get_registry_value(handle:hklm, item:dbaid_key);
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

dbg::log(src:SCRIPT_NAME,msg:"found DBAID key with value : " + dbaid_key_val);

# Mitigation reads:
# If not applying a recommended remediation listed above, using an administrator account check for the following
# registry key.
# "Software\Veritas\Backup Exec For Windows\Backup Exec\Engine\Agents\XBSA\Machine\DBAID"
# If the registry key exists and the DBAID value is set to a non-zero value, no further action is required.
# If the registry key does not exist, create the registry key of type string (REG_SZ) and set the value of DBAID to a 
# random hexadecimal string of the form “UIBj_?@BNo8hjR;1RW>3L1h\onZ^acSJC`7^he<2S;l”. This will prevent an attacker
# from using the SHA authentication scheme.
# So, seems like we can just check that the key is not empty or 0.
if (!(dbaid_key_val == "") || !(dbaid_key_val == 0))
{
  audit(AUDIT_OS_CONF_NOT_VULN, 'Veritas Backup Exec Remote Agent', app_info.version);
}

constraints = [
  { 'min_version' : '16.0', 'fixed_version' : '21.0.1200.1899' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
