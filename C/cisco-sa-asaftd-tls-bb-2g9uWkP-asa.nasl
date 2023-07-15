#TRUSTED 05d5e3a22897303c4edb02b683a2dd51fc7e48874c7f8ad8848383d54d3c599737c73f0f1dceaf35776cdc92dfd812f9ce7643ce7bea4e8b33f45df192ecae94a1cff50fca19bba8296d0140ec0cff6cfd93e885cae384adc2da23aef9b1b37f21ca7ed90523338437ed3c4a634a3b2181e436c3cef996eb207681c0c1543b27697380dde0f4243369be6e6aea6799fa8ccd0892662d764b9c67f038639e42b598a8fa1cd128b01d9a5c56a6d263defb769ea883c2281e13a3cae5807b2d62ba165ecd9a0a987124e653b7ac5c04ee236b9ff73388a65e1f14483a1ceb7fa501711d371984e5beb8487c018f80a1632439263b23aa36a252ddf4cb643ee303a891097afba8e679eed1f5c789656ddae6b6d4304360a565af0bbe54792f87b013ec665087b12b4fd0fffc52887ea0bad39a2fc5c00c6d3cbdefaee8b44c2d8841f806d4d0bd1e07dad4d861a35be0fc75708392ab4468fb6ce6b64b9ca8a9e0b3beb2886ac7a49940556b53bfda14d81d4298e7959faa3dacc9f5a8033e4e332391dd5ac3de1985c66b6465cad6c93a9629819bb3f1deb13f2db41596a8a7db13929db0d153d1f8300fbaa6dadfe7b04553c4ea623485c290d36a51656e77ac147bba26c8371ccdf38a28a41fd6f733e0c4bcb7529e77ea12edd1aee1d27c01289f2ec815ef72b6685c3067498365ca3596e56230d0a6f5a2469da6faa8f09635
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149470);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/17");

  script_cve_id("CVE-2020-3585");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv13993");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-tls-bb-2g9uWkP");

  script_name(english:"Cisco Adaptive Security Appliance Software Bleichenbacher Attack (cisco-sa-asaftd-tls-bb-2g9uWkP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the TLS handler of Cisco Adaptive Security Appliance (ASA) Software for Cisco 
Firepower 1000 is affected by the Bleichenbacher attack vulnerability due to improper implementation of countermeasures 
against the Bleichenbacher attack for cipher suites that rely on RSA for key exchange. An unauthenticated, 
remote attacker can exploit this by sending crafted TLS messages to the device, which would act as an oracle and allow 
the attacker to carry out a chosen-ciphertext attack. A successful exploit could allow the attacker to perform 
cryptanalytic operations that may allow decryption of previously captured TLS sessions to the affected device. To exploit 
this vulnerability, an attacker must be able to capture TLS traffic that is in transit between clients and the 
affected device, and actively establish a considerable number of TLS connections to the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tls-bb-2g9uWkP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c27f3ff");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv13993");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv13993");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(203);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');
    
# Vulnerable model list Cisco Firepower 1000 Series firewalls FPR-1000
if (product_info['model'] !~ "(1[0-9]{3}|1K)")
    audit(AUDIT_DEVICE_NOT_VULN, 'The ' + product_info['model'] + ' model');

var vuln_ranges = [
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1.13'},
  {'min_ver' : '9.14',  'fix_ver' : '9.14.1.30'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['asa_ssl_tls'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv13993',
  'cmds'     , make_list('show asp table socket')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);