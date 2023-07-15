#TRUSTED 48703d2487cbbc65d62b7a0d497eaeed2c960279a26bac8daf57859f1e0d6067b1284b8ab9a41d36122da6f01f74a47cd95b5824a9d850adf8ebc07b4f1b1b5497f9101c50052fa7a2b91fe207cdd62f16a88494023e263329b3c86a88d5326817a9c1d8779f5de565b2aa088f54fdfb21f25128740b7f66424ea1104084deb168685716493ea06e4d02aa12f2a2c5bef95fa2f288be7425c9c918561c7cb1f3b183a499b6982686d8c22fecfa658a48026cf210114c8cdd92704ff113a34059c21d8ecf1d9d982facc10eb561ed31bb601f3c7374b9381208a98d12813b0c57a5cb3d049e0d2811c95cbc88af3aa4cf01a59bf3bb4b08d257642df00818055898b9961bcd2bef437b9321a1988eab8e05af4f877c29eb24779f7095b81ab5aada53068cc6aa41aaa455adab9c0b8f9d367098ada33c82c2f1377e2a387bd2fda18b9ed48d1800a3edf4f69b6bbd582df9c4e91c44e9f005ce5faf774ecdbf852bfc08fa89d44fb6abf3e003569c3262a8d53965ef9146580ad1c4017e1294007524ed06287811b45b2148bac89fea88f91f774a42812cb03921c5d51e79d9941bca57258457df64d2f6811141dcc5639ac6728e0b968854fe161a7d795b792244ec8826a795e87f86ca1f9cb95a4b75760d76e052da1b44a8c246ac269b2f616e37dc4ff68f14ea902e26676b8b182dbf3763c3d52a389696cb74df8e59ec7d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152658);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2021-1451");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv66062");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-evss-code-exe-8cw5VSvw");

  script_name(english:"Cisco IOS XE Software Arbitrary Code Execution (cisco-sa-ios-xe-evss-code-exe-8cw5VSvw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by an arbitrary code execution vulnerability.
An unauthenticated, remote attacker can execute arbitrary code on the underlying Linux operating system of an affected
device. The vulnerability is due to incorrect boundary checks of certain values in Easy VSS protocol packets that are
destined for an affected device. An attacker could exploit this vulnerability by sending crafted Easy VSS protocol
packets to UDP port 5500 while the affected device is in a specific state. When the crafted packet is processed,
a buffer overflow condition may occur. A successful exploit could allow the attacker to trigger a denial of service
(DoS) condition or execute arbitrary code with root privileges on the underlying Linux operating system of the affected
device. Please see the included Cisco BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-evss-code-exe-8cw5VSvw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31e22e34");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv66062");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv66062");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1451");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);
    
# Vulnerable model list
if (model !~ 'C45')
    audit(AUDIT_HOST_NOT, 'affected');

var version_list = make_list(
  '3.6.0E',
  '3.6.0bE',
  '3.6.1E',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.6E',
  '3.6.7E',
  '3.6.8E',
  '3.6.9E',
  '3.6.10E',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '3.8.9E',
  '3.8.10E',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2aE',
  '3.11.3E',
  '3.11.3aE',
  '16.11.2',
  '16.12.5a',
  '17.3.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['vss'], CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['virtual_switch_mode'];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvv66062',
  'cmds'     , make_list('show running-config', 'show cdp','show switch virtual'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params,
  require_all_workarounds:TRUE
);
