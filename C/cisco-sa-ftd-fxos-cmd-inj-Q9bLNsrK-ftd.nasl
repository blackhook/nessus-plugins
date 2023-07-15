#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168646);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/13");

  script_cve_id("CVE-2022-20934");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-fxos-cmd-inj-Q9bLNsrK");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb41854");
  script_xref(name:"IAVA", value:"2022-A-0486");

  script_name(english:"Cisco Firepower Threat Defense Software Command Injection (cisco-sa-ftd-fxos-cmd-inj-Q9bLNsrK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the CLI of Cisco FTD Software could allow an authenticated, local attacker to inject
arbitrary commands that are executed with root privileges. The attacker would need to have Administrator
privileges on the device. This vulnerability is due to insufficient input validation of commands supplied
by the user. An attacker could exploit this vulnerability by authenticating to a device and submitting
crafted input to the affected command. A successful exploit could allow the attacker to execute commands
on the underlying operating system with root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74838");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-fxos-cmd-inj-Q9bLNsrK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45540201");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb41854");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb41854");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var version_list = NULL;

if (product_info['model'] =~ '([^0-9]|^)1[0-9]{3}')
  version_list = [
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
    '6.6.7',
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
    '7.0.4',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1',
  ];
else if (product_info['model'] =~ '([^0-9]|^)21[0-9]{2}')
  version_list = [
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
    '6.6.7',
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
    '7.0.4',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  ];
else if (product_info['model'] =~ '([^0-9]|^)(41|9[0-3])[0-9]{2}' || 'NGFW' >< product_info['model'])
  version_list = [
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
    '6.6.7',
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
    '7.0.4',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  ];
else if (product_info['model'] =~ 'ASA ?55[0-9]{2}-X')
  version_list = [
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
    '6.6.7',
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
    '7.0.4'
  ];
else if (product_info['model'] =~ 'ISA[ -]?3[0-9]{3}')
  version_list = [
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
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.3.0',
    '6.6.7',
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
    '7.0.4',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  ];
else if (product_info['model'] =~ '(^|[^0-9])31[0-9]{2}')
  version_list = [
    '7.1.0',
    '7.1.0.2',
    '7.2.0',
    '7.2.0.1'
  ];
else
  audit(AUDIT_DEVICE_NOT_VULN, 'The ' + product_info['model'] + ' model');


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwb41854',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
