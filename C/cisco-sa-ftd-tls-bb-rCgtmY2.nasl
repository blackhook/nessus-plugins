#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173792);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2022-20940");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa41936");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-tls-bb-rCgtmY2");
  script_xref(name:"IAVA", value:"2022-A-0486");

  script_name(english:"Cisco Firepower Threat Defense Software SSL Decryption Policy Bleichenbacher Attack (cisco-sa-ftd-tls-bb-rCgtmY2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the TLS handler of Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, 
remote attacker to gain access to sensitive information. This vulnerability is due to improper implementation of 
countermeasures against a Bleichenbacher attack on a device that uses SSL decryption policies. An attacker could 
exploit this vulnerability by sending crafted TLS messages to an affected device, which would act as an oracle and 
allow the attacker to carry out a chosen-ciphertext attack. A successful exploit could allow the attacker to perform 
cryptanalytic operations that may allow decryption of previously captured TLS sessions to the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-tls-bb-rCgtmY2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48c077a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa41936");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20940");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

# Paranoid since we cant determine the SSL Decryption Policy Configuration via cli
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var is_ASA = get_kb_item('Host/Cisco/ASA');

var model = product_info['model'];

# Cisco Firepower 2100 Series
# Cisco 3000 Series Industrial Security Appliances (ISA)
# Cisco Firepower 9000 Series
# Cisco Firepower 4100 Series
# Cisco Firepower NGFW Virtual
# Cisco Secure Firewall 3100 Series
# Cisco ASA 5500-X Series Firewalls
# Cisco Firepower 1000 Series
if (model !~ "FPR-?([19][0-9]{3}|[24]1[0-9]{2})|ASA\s?55[0-9]{2}-X|NGFW|ISA3[0-9]{3}|Secure.*31[0-9]{2}")
    audit(AUDIT_HOST_NOT, 'an affected model');

# common version for some most of the models mentioned below
var version_list = [
    '6.6.0', 
    '6.6.0.1', 
    '6.6.1', 
    '6.6.3', 
    '6.6.4', 
    '6.6.5', 
    '6.6.5.1', 
    '6.6.5.2', 
    '6.4.0', 
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
];

# Cisco Firepower 1000 Series
if (model =~ "FPR-1[0-9]{3}")
{
  append_element(var:version_list, value:'7.1.0');
  append_element(var:version_list, value:'7.1.0.1');
}

# Cisco Firepower 2100 Series
# Cisco 3000 Series Industrial Security Appliances (ISA)
# Cisco Firepower 9000 Series
# Cisco Firepower 4100 Series
# Cisco Firepower NGFW Virtual
else if (model =~ "ISA3[0-9]{3}" || (model =~ "NGFW") || (model =~ "FPR-((21|41)[0-9]{2}|((9)[0-9]{3}))"))
{
  append_element(var:version_list, value:'6.2.3.1');
  append_element(var:version_list, value:'6.2.3.2');
  append_element(var:version_list, value:'6.2.3.3');
  append_element(var:version_list, value:'6.2.3.4');
  append_element(var:version_list, value:'6.2.3.5');
  append_element(var:version_list, value:'6.2.3.6');
  append_element(var:version_list, value:'6.2.3.7');
  append_element(var:version_list, value:'6.2.3.8');
  append_element(var:version_list, value:'6.2.3.10');
  append_element(var:version_list, value:'6.2.3.11');
  append_element(var:version_list, value:'6.2.3.9');
  append_element(var:version_list, value:'6.2.3.12');
  append_element(var:version_list, value:'6.2.3.13');
  append_element(var:version_list, value:'6.2.3.14');
  append_element(var:version_list, value:'6.2.3.15');
  append_element(var:version_list, value:'6.2.3.16');
  append_element(var:version_list, value:'6.2.3.17');
  append_element(var:version_list, value:'6.2.3.18');
  append_element(var:version_list, value:'6.3.0');
  append_element(var:version_list, value:'6.3.0.1');
  append_element(var:version_list, value:'6.3.0.2');
  append_element(var:version_list, value:'6.3.0.3');
  append_element(var:version_list, value:'6.3.0.4');
  append_element(var:version_list, value:'6.3.0.5');
  append_element(var:version_list, value:'6.4.0.1');
  append_element(var:version_list, value:'7.1.0');
  append_element(var:version_list, value:'7.1.0.1');
}

# Cisco ASA 5500-X Series Firewalls
else if (is_ASA && model =~ "-X")
{
  append_element(var:version_list, value:'6.2.3.1');
  append_element(var:version_list, value:'6.2.3.2');
  append_element(var:version_list, value:'6.2.3.3');
  append_element(var:version_list, value:'6.2.3.4');
  append_element(var:version_list, value:'6.2.3.5');
  append_element(var:version_list, value:'6.2.3.6');
  append_element(var:version_list, value:'6.2.3.7');
  append_element(var:version_list, value:'6.2.3.8');
  append_element(var:version_list, value:'6.2.3.10');
  append_element(var:version_list, value:'6.2.3.11');
  append_element(var:version_list, value:'6.2.3.9');
  append_element(var:version_list, value:'6.2.3.12');
  append_element(var:version_list, value:'6.2.3.13');
  append_element(var:version_list, value:'6.2.3.14');
  append_element(var:version_list, value:'6.2.3.15');
  append_element(var:version_list, value:'6.2.3.16');
  append_element(var:version_list, value:'6.2.3.17');
  append_element(var:version_list, value:'6.2.3.18');
  append_element(var:version_list, value:'6.3.0');
  append_element(var:version_list, value:'6.3.0.1');
  append_element(var:version_list, value:'6.3.0.2');
  append_element(var:version_list, value:'6.3.0.3');
  append_element(var:version_list, value:'6.3.0.4');
  append_element(var:version_list, value:'6.3.0.5');
  append_element(var:version_list, value:'6.4.0.1');
}

# Cisco Secure Firewall 3100 Series
else if (model =~ "Secure.*31[0-9]{2}")
{
  var version_list = [
    '7.1.0', 
    '7.1.0.1'
  ];
}
else
  audit(AUDIT_HOST_NOT, 'an affected model');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa41936',
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_versions:version_list
);
