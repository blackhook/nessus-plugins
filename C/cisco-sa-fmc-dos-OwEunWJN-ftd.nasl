#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168870);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/19");

  script_cve_id("CVE-2022-20854");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy95520");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-dos-OwEunWJN");

  script_name(english:"Cisco Firepower Threat Defense Software SSH DoS (cisco-sa-fmc-dos-OwEunWJN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firepower Threat Defense installed on the remote host is affected by a vulnerability in the 
processing of SSH connections of Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote
attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper 
error handling when an SSH session fails to be established. An attacker could exploit this vulnerability by sending a 
high rate of crafted SSH connections to the instance. A successful exploit could allow the attacker to cause resource 
exhaustion, resulting in a reboot on the affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-dos-OwEunWJN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a73e7c9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy95520");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy95520");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20854");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
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

var model = product_info['model'];

# Cisco Firepower 2100 Series
# Cisco 3000 Series Industrial Security Appliances (ISA)
# Cisco Firepower 9000 Series
# Cisco Firepower 4100 Series
# Cisco Firepower NGFW Virtual
# Cisco ASA 5500-X Series Firewalls
# Cisco Firepower 1000 Series

if (model !~ "(FPR-|Firepower\s?)([19][0-9]{3}|[24]1[0-9]{2})|ASA[\s-]??55[0-9]{2}-X|NGFW|ISA[\s-]?3[0-9]{3}")
    audit(AUDIT_HOST_NOT, 'an affected model');

# common version for some most of the models mentioned below
# and also version list for Cisco Firepower 1000 Series
var version_list = [
    '6.4.0.10',
    '6.4.0.11',
    '6.4.0.12',
    '6.4.0.13',
    '6.4.0.14',
    '6.4.0.15',
    '6.4.0.2',
    '6.4.0.3',
    '6.4.0.4',
    '6.4.0.5',
    '6.4.0.6',
    '6.4.0.7',
    '6.4.0.8',
    '6.4.0.9',
    '6.4.0',
    '6.5.0.1',
    '6.5.0.2',
    '6.5.0.3',
    '6.5.0.4',
    '6.5.0.5',
    '6.5.0',
    '6.6.0.1',
    '6.6.0',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5.1',
    '6.6.5.2',
    '6.6.5',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '6.7.0',
    '7.0.0.1',
    '7.0.0',
    '7.0.1.1',
    '7.0.1',
    '7.0.2.1',
    '7.0.2',
    '7.0.3',
    '7.0.4',
    '7.1.0.1',
    '7.1.0'
];

# Cisco 3000 Series Industrial Security Appliances (ISA)
if (model =~ "ISA[\s-]?3[0-9]{3}")
{
  append_element(var:version_list, value:'6.2.3.1');
  append_element(var:version_list, value:'6.2.3.10');
  append_element(var:version_list, value:'6.2.3.11');
  append_element(var:version_list, value:'6.2.3.12');
  append_element(var:version_list, value:'6.2.3.13');
  append_element(var:version_list, value:'6.2.3.14');
  append_element(var:version_list, value:'6.2.3.15');
  append_element(var:version_list, value:'6.2.3.16');
  append_element(var:version_list, value:'6.2.3.17');
  append_element(var:version_list, value:'6.2.3.18');
  append_element(var:version_list, value:'6.2.3.2');
  append_element(var:version_list, value:'6.2.3.3');
  append_element(var:version_list, value:'6.2.3.4');
  append_element(var:version_list, value:'6.2.3.5');
  append_element(var:version_list, value:'6.2.3.6');
  append_element(var:version_list, value:'6.2.3.7');
  append_element(var:version_list, value:'6.2.3.8');
  append_element(var:version_list, value:'6.2.3.9');
  append_element(var:version_list, value:'6.2.3');
  append_element(var:version_list, value:'6.3.0.1');
  append_element(var:version_list, value:'6.3.0.2');
  append_element(var:version_list, value:'6.3.0.3');
  append_element(var:version_list, value:'6.3.0.4');
  append_element(var:version_list, value:'6.3.0.5');
  append_element(var:version_list, value:'6.3.0');
  append_element(var:version_list, value:'6.4.0.1');
}

# Cisco Firepower 2100 Series
else if (model =~ "(FPR-|Firepower\s?)21[0-9]{2}")
{
  append_element(var:version_list, value:'6.2.1');
  append_element(var:version_list, value:'6.2.2.1');
  append_element(var:version_list, value:'6.2.2.2');
  append_element(var:version_list, value:'6.2.2.3');
  append_element(var:version_list, value:'6.2.2.4');
  append_element(var:version_list, value:'6.2.2.5');
  append_element(var:version_list, value:'6.2.2');
  append_element(var:version_list, value:'6.2.3.1');
  append_element(var:version_list, value:'6.2.3.10');
  append_element(var:version_list, value:'6.2.3.11');
  append_element(var:version_list, value:'6.2.3.12');
  append_element(var:version_list, value:'6.2.3.13');
  append_element(var:version_list, value:'6.2.3.14');
  append_element(var:version_list, value:'6.2.3.15');
  append_element(var:version_list, value:'6.2.3.16');
  append_element(var:version_list, value:'6.2.3.17');
  append_element(var:version_list, value:'6.2.3.18');
  append_element(var:version_list, value:'6.2.3.2');
  append_element(var:version_list, value:'6.2.3.3');
  append_element(var:version_list, value:'6.2.3.4');
  append_element(var:version_list, value:'6.2.3.5');
  append_element(var:version_list, value:'6.2.3.6');
  append_element(var:version_list, value:'6.2.3.7');
  append_element(var:version_list, value:'6.2.3.8');
  append_element(var:version_list, value:'6.2.3.9');
  append_element(var:version_list, value:'6.2.3');
  append_element(var:version_list, value:'6.3.0.1');
  append_element(var:version_list, value:'6.3.0.2');
  append_element(var:version_list, value:'6.3.0.3');
  append_element(var:version_list, value:'6.3.0.4');
  append_element(var:version_list, value:'6.3.0.5');
  append_element(var:version_list, value:'6.3.0');
  append_element(var:version_list, value:'6.4.0.1');
}

# Cisco ASA 5500-X Series Firewalls
else if (model =~ "ASA[\s-]??55[0-9]{2}-X")
{
  append_element(var:version_list, value:'6.1.0.1');
  append_element(var:version_list, value:'6.1.0.2');
  append_element(var:version_list, value:'6.1.0.3');
  append_element(var:version_list, value:'6.1.0.4');
  append_element(var:version_list, value:'6.1.0.5');
  append_element(var:version_list, value:'6.1.0.6');
  append_element(var:version_list, value:'6.1.0.7');
  append_element(var:version_list, value:'6.1.0');
  append_element(var:version_list, value:'6.2.0.1');
  append_element(var:version_list, value:'6.2.0.2');
  append_element(var:version_list, value:'6.2.0.3');
  append_element(var:version_list, value:'6.2.0.4');
  append_element(var:version_list, value:'6.2.0.5');
  append_element(var:version_list, value:'6.2.0.6');
  append_element(var:version_list, value:'6.2.0');
  append_element(var:version_list, value:'6.2.2.1');
  append_element(var:version_list, value:'6.2.2.2');
  append_element(var:version_list, value:'6.2.2.3');
  append_element(var:version_list, value:'6.2.2.4');
  append_element(var:version_list, value:'6.2.2.5');
  append_element(var:version_list, value:'6.2.2');
  append_element(var:version_list, value:'6.2.3.1');
  append_element(var:version_list, value:'6.2.3.10');
  append_element(var:version_list, value:'6.2.3.11');
  append_element(var:version_list, value:'6.2.3.12');
  append_element(var:version_list, value:'6.2.3.13');
  append_element(var:version_list, value:'6.2.3.14');
  append_element(var:version_list, value:'6.2.3.15');
  append_element(var:version_list, value:'6.2.3.16');
  append_element(var:version_list, value:'6.2.3.17');
  append_element(var:version_list, value:'6.2.3.18');
  append_element(var:version_list, value:'6.2.3.2');
  append_element(var:version_list, value:'6.2.3.3');
  append_element(var:version_list, value:'6.2.3.4');
  append_element(var:version_list, value:'6.2.3.5');
  append_element(var:version_list, value:'6.2.3.6');
  append_element(var:version_list, value:'6.2.3.7');
  append_element(var:version_list, value:'6.2.3.8');
  append_element(var:version_list, value:'6.2.3.9');
  append_element(var:version_list, value:'6.2.3');
  append_element(var:version_list, value:'6.3.0.1');
  append_element(var:version_list, value:'6.3.0.2');
  append_element(var:version_list, value:'6.3.0.3');
  append_element(var:version_list, value:'6.3.0.4');
  append_element(var:version_list, value:'6.3.0.5');
  append_element(var:version_list, value:'6.3.0');
  append_element(var:version_list, value:'6.4.0.1');
}

# Cisco Firepower 9000 Series
# Cisco Firepower 4100 Series
# Cisco Firepower NGFW Virtual
else if ((model =~ "NGFW") || (model =~ "(FPR-|Firepower\s?)(41[0-9]{2}|((9)[0-9]{3}))"))
{
  append_element(var:version_list, value:'6.1.0.1');
  append_element(var:version_list, value:'6.1.0.2');
  append_element(var:version_list, value:'6.1.0.3');
  append_element(var:version_list, value:'6.1.0.4');
  append_element(var:version_list, value:'6.1.0.5');
  append_element(var:version_list, value:'6.1.0.6');
  append_element(var:version_list, value:'6.1.0.7');
  append_element(var:version_list, value:'6.1.0');
  append_element(var:version_list, value:'6.2.0.1');
  append_element(var:version_list, value:'6.2.0.2');
  append_element(var:version_list, value:'6.2.0.3');
  append_element(var:version_list, value:'6.2.0.4');
  append_element(var:version_list, value:'6.2.0.5');
  append_element(var:version_list, value:'6.2.0.6');
  append_element(var:version_list, value:'6.2.0');
  append_element(var:version_list, value:'6.2.2.1');
  append_element(var:version_list, value:'6.2.2.2');
  append_element(var:version_list, value:'6.2.2.3');
  append_element(var:version_list, value:'6.2.2.4');
  append_element(var:version_list, value:'6.2.2.5');
  append_element(var:version_list, value:'6.2.2');
  append_element(var:version_list, value:'6.2.3.1');
  append_element(var:version_list, value:'6.2.3.10');
  append_element(var:version_list, value:'6.2.3.11');
  append_element(var:version_list, value:'6.2.3.12');
  append_element(var:version_list, value:'6.2.3.13');
  append_element(var:version_list, value:'6.2.3.14');
  append_element(var:version_list, value:'6.2.3.15');
  append_element(var:version_list, value:'6.2.3.16');
  append_element(var:version_list, value:'6.2.3.17');
  append_element(var:version_list, value:'6.2.3.18');
  append_element(var:version_list, value:'6.2.3.2');
  append_element(var:version_list, value:'6.2.3.3');
  append_element(var:version_list, value:'6.2.3.4');
  append_element(var:version_list, value:'6.2.3.5');
  append_element(var:version_list, value:'6.2.3.6');
  append_element(var:version_list, value:'6.2.3.7');
  append_element(var:version_list, value:'6.2.3.8');
  append_element(var:version_list, value:'6.2.3.9');
  append_element(var:version_list, value:'6.2.3');
  append_element(var:version_list, value:'6.3.0.1');
  append_element(var:version_list, value:'6.3.0.2');
  append_element(var:version_list, value:'6.3.0.3');
  append_element(var:version_list, value:'6.3.0.4');
  append_element(var:version_list, value:'6.3.0.5');
  append_element(var:version_list, value:'6.3.0');
  append_element(var:version_list, value:'6.4.0.1');
}

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy95520',
  'fix'           , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
