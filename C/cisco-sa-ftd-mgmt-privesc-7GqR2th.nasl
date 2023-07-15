#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170015);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/16");

  script_cve_id("CVE-2022-20949");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb52401");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-mgmt-privesc-7GqR2th");
  script_xref(name:"IAVA", value:"2022-A-0486");

  script_name(english:"Cisco Firepower Threat Defense Software Privilege Escalation (cisco-sa-ftd-mgmt-privesc-7GqR2th)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the management web server of Cisco Firepower Threat Defense (FTD) Software could allow an 
authenticated, remote attacker with high privileges to execute configuration commands on an affected system.
This vulnerability exists because access to HTTPS endpoints is not properly restricted on an affected device. An 
attacker could exploit this vulnerability by sending specific messages to the affected HTTPS handler. A successful 
exploit could allow the attacker to perform configuration changes on the affected system, which should be configured 
and managed only through Cisco Firepower Management Center (FMC) Software.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-mgmt-privesc-7GqR2th
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76a892da");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74838");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb52401");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb52401");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20949");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
var model = product_info['model'];
var vuln_versions = NULL;

# Cisco 3000 Series Industrial Security Appliances (ISA)
if (model =~ "ISA3[0-9]{3}")
{
  vuln_versions = make_list(
    '6.2.3',
    '6.2.3.1',
    '6.2.3.2',
    '6.2.3.3',
    '6.2.3.4',
    '6.2.3.5',
    '6.2.3.6',
    '6.2.3.7',
    '6.2.3.8',
    '6.2.3.10',
    '6.2.3.11',
    '6.2.3.9',
    '6.2.3.12',
    '6.2.3.13',
    '6.2.3.14',
    '6.2.3.15',
    '6.2.3.16',
    '6.2.3.17',
    '6.2.3.18',
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.3.0',
    '6.3.0.1',
    '6.3.0.2',
    '6.3.0.3',
    '6.3.0.4',
    '6.3.0.5',
    '6.4.0',
    '6.4.0.1',
    '6.4.0.3',
    '6.4.0.2',
    '6.4.0.4',
    '6.4.0.5',
    '6.4.0.6',
    '6.4.0.7',
    '6.4.0.8',
    '6.4.0.9',
    '6.4.0.10',
    '6.4.0.11',
    '6.4.0.12',
    '6.4.0.13',
    '6.4.0.14',
    '6.4.0.15',
    '6.5.0',
    '6.5.0.2',
    '6.5.0.4',
    '6.5.0.1',
    '6.5.0.3',
    '6.5.0.5',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  );
}
# Cisco ASA 5500-X Series Firewalls
else if (model =~ "ASA55[0-9]{2}-X")
{
  vuln_versions = make_list(
    '6.1.0',
    '6.1.0.2',
    '6.1.0.1',
    '6.1.0.3',
    '6.1.0.4',
    '6.1.0.5',
    '6.1.0.6',
    '6.1.0.7',
    '6.2.0',
    '6.2.2',
    '6.2.0.1',
    '6.2.0.2',
    '6.2.0.3',
    '6.2.0.4',
    '6.2.2.1',
    '6.2.2.2',
    '6.2.3',
    '6.2.3.1',
    '6.2.3.2',
    '6.2.3.3',
    '6.2.3.4',
    '6.2.3.5',
    '6.2.2.3',
    '6.2.2.4',
    '6.2.0.5',
    '6.2.0.6',
    '6.2.3.6',
    '6.2.2.5',
    '6.2.3.7',
    '6.2.3.8',
    '6.2.3.10',
    '6.2.3.11',
    '6.2.3.9',
    '6.2.3.12',
    '6.2.3.13',
    '6.2.3.14',
    '6.2.3.15',
    '6.2.3.16',
    '6.2.3.17',
    '6.2.3.18',
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.3.0',
    '6.3.0.1',
    '6.3.0.2',
    '6.3.0.3',
    '6.3.0.4',
    '6.3.0.5',
    '6.4.0',
    '6.4.0.1',
    '6.4.0.3',
    '6.4.0.2',
    '6.4.0.4',
    '6.4.0.5',
    '6.4.0.6',
    '6.4.0.7',
    '6.4.0.8',
    '6.4.0.9',
    '6.4.0.10',
    '6.4.0.11',
    '6.4.0.12',
    '6.4.0.13',
    '6.4.0.14',
    '6.4.0.15',
    '6.5.0',
    '6.5.0.2',
    '6.5.0.4',
    '6.5.0.1',
    '6.5.0.3',
    '6.5.0.5',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3'
  );
}
# Cisco Firepower 1000 Series
else if (model =~ "(FPR-?|Firepower)\s*(1[0-9]{3}|1K)")
{
  vuln_versions = make_list(
    '6.4.0',
    '6.4.0.2',
    '6.4.0.3',
    '6.4.0.4',
    '6.4.0.5',
    '6.4.0.6',
    '6.4.0.7',
    '6.4.0.8',
    '6.4.0.9',
    '6.4.0.10',
    '6.4.0.11',
    '6.4.0.12',
    '6.4.0.13',
    '6.4.0.14',
    '6.4.0.15',
    '6.5.0',
    '6.5.0.1',
    '6.5.0.2',
    '6.5.0.3',
    '6.5.0.4',
    '6.5.0.5',
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  );
}
# Cisco Firepower 2100 Series
else if (model =~ "(FPR-?|Firepower)\s*(21[0-9]{2}|2K)")
{
  vuln_versions = make_list(
    '6.2.1',
    '6.2.2',
    '6.2.2.1',
    '6.2.2.2',
    '6.2.2.3',
    '6.2.2.4',
    '6.2.2.5',
    '6.2.3',
    '6.2.3.1',
    '6.2.3.2',
    '6.2.3.3',
    '6.2.3.4',
    '6.2.3.5',
    '6.2.3.6',
    '6.2.3.7',
    '6.2.3.8',
    '6.2.3.9',
    '6.2.3.10',
    '6.2.3.11',
    '6.2.3.12',
    '6.2.3.13',
    '6.2.3.14',
    '6.2.3.15',
    '6.2.3.16',
    '6.2.3.17',
    '6.2.3.18',
    '6.3.0',
    '6.3.0.1',
    '6.3.0.2',
    '6.3.0.3',
    '6.3.0.4',
    '6.3.0.5',
    '6.4.0',
    '6.4.0.1',
    '6.4.0.2',
    '6.4.0.3',
    '6.4.0.4',
    '6.4.0.5',
    '6.4.0.6',
    '6.4.0.7',
    '6.4.0.8',
    '6.4.0.9',
    '6.4.0.10',
    '6.4.0.11',
    '6.4.0.12',
    '6.4.0.13',
    '6.4.0.14',
    '6.4.0.15',
    '6.5.0',
    '6.5.0.1',
    '6.5.0.2',
    '6.5.0.3',
    '6.5.0.4',
    '6.5.0.5',
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  );
}
# Cisco Firepower 4100, 9000 Series
else if (model =~ "(FPR-?|Firepower)\s*(41[0-9]{2}|4K|9[0-9]{3}|9K)")
{
  vuln_versions = make_list(
    '6.1.0',
    '6.1.0.1',
    '6.1.0.2',
    '6.1.0.3',
    '6.1.0.4',
    '6.1.0.5',
    '6.1.0.6',
    '6.1.0.7',
    '6.2.0',
    '6.2.0.1',
    '6.2.0.2',
    '6.2.0.3',
    '6.2.0.4',
    '6.2.0.5',
    '6.2.0.6',
    '6.2.2',
    '6.2.2.1',
    '6.2.2.2',
    '6.2.2.3',
    '6.2.2.4',
    '6.2.2.5',
    '6.2.3',
    '6.2.3.1',
    '6.2.3.2',
    '6.2.3.3',
    '6.2.3.4',
    '6.2.3.5',
    '6.2.3.6',
    '6.2.3.7',
    '6.2.3.8',
    '6.2.3.9',
    '6.2.3.10',
    '6.2.3.11',
    '6.2.3.12',
    '6.2.3.13',
    '6.2.3.14',
    '6.2.3.15',
    '6.2.3.16',
    '6.2.3.17',
    '6.2.3.18',
    '6.3.0',
    '6.3.0.1',
    '6.3.0.2',
    '6.3.0.3',
    '6.3.0.4',
    '6.3.0.5',
    '6.4.0',
    '6.4.0.1',
    '6.4.0.2',
    '6.4.0.3',
    '6.4.0.4',
    '6.4.0.5',
    '6.4.0.6',
    '6.4.0.7',
    '6.4.0.8',
    '6.4.0.9',
    '6.4.0.10',
    '6.4.0.11',
    '6.4.0.12',
    '6.4.0.13',
    '6.4.0.14',
    '6.4.0.15',
    '6.5.0',
    '6.5.0.1',
    '6.5.0.2',
    '6.5.0.3',
    '6.5.0.4',
    '6.5.0.5',
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  );
}
# Cisco Firepower NGFW Virtual
else if ('NGFW' >< toupper(model))
{
  vuln_versions = make_list(
    '6.1.0',
    '6.1.0.2',
    '6.1.0.1',
    '6.1.0.3',
    '6.1.0.4',
    '6.1.0.5',
    '6.1.0.6',
    '6.1.0.7',
    '6.2.0',
    '6.2.2',
    '6.2.0.1',
    '6.2.0.2',
    '6.2.0.3',
    '6.2.0.4',
    '6.2.2.1',
    '6.2.2.2',
    '6.2.3',
    '6.2.3.1',
    '6.2.3.2',
    '6.2.3.3',
    '6.2.3.4',
    '6.2.3.5',
    '6.2.2.3',
    '6.2.2.4',
    '6.2.0.5',
    '6.2.0.6',
    '6.2.3.6',
    '6.2.2.5',
    '6.2.3.7',
    '6.2.3.8',
    '6.2.3.10',
    '6.2.3.11',
    '6.2.3.9',
    '6.2.3.12',
    '6.2.3.13',
    '6.2.3.14',
    '6.2.3.15',
    '6.2.3.16',
    '6.2.3.17',
    '6.2.3.18',
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.3.0',
    '6.3.0.1',
    '6.3.0.2',
    '6.3.0.3',
    '6.3.0.4',
    '6.3.0.5',
    '6.4.0',
    '6.4.0.1',
    '6.4.0.3',
    '6.4.0.2',
    '6.4.0.4',
    '6.4.0.5',
    '6.4.0.6',
    '6.4.0.7',
    '6.4.0.8',
    '6.4.0.9',
    '6.4.0.10',
    '6.4.0.11',
    '6.4.0.12',
    '6.4.0.13',
    '6.4.0.14',
    '6.4.0.15',
    '6.5.0',
    '6.5.0.2',
    '6.5.0.4',
    '6.5.0.1',
    '6.5.0.3',
    '6.5.0.5',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  );
}
# Cisco Secure Firewall 3100 Series
else if (report_paranoia >= 2)
{
  vuln_versions = make_list(
    '7.1.0',
    '7.1.0.2',
    '7.2.0',
    '7.2.0.1'
  );
}
else audit(AUDIT_HOST_NOT, 'an affected model');

var workarounds, workaround_params;
var is_ftd_cli = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwb52401',
  'fix'     , 'See vendor advisory'
);

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  workarounds = make_list();
  reporting.extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  # conditions: (a) FTD managed by FMC & (b) HTTPS access configured & (c) ACLs associated with ifaces
  workaround_params = [
    WORKAROUND_CONFIG['ftd_connected_to_fmc'],
    WORKAROUND_CONFIG['ASA_HTTP_Server'],
    WORKAROUND_CONFIG['ftd_http_acl'],
    {'require_all_generic_workarounds': TRUE}
  ];
  reporting.cmds = make_list('show running-config, show managers');
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
