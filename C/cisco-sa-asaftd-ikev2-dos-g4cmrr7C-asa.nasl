#TRUSTED 6d121d6f16a9cff1721df8831d3bff9df9f7bb6ee732ce2c6147ce9f2bbccf4235df58a7a3869f02bf5568475763ce3f472581e50bc03d2f26b4a09e48417e6af1115f4173d0952091d4c4c77eb7a420d369bb2fbf029bbf26e612594de760fa039fad51b569550e03068e9499675d7c53fa3030900fa347dc7aeea246f0deae87e1a5171ee1fb43108efbb84c20166f14386a6f05c32c0a6013bd85ec3da55683d8c43c0eb1eb980d04b077256757178c992280d8474358d4526b95e09382eeb466bbf8c38d664373f2d62854210c4f716e6695346e3233d83e45c53de220fe9861c305223ae0f34edb16e98ff2239a9f744e20773abd68af5717fa63697f61b032bbbe7a2c3107d49f61a5746cdf0a18764c786892aa1a5d984f9878b001863c6819ee79b89e933be47eb3decac308a1bfc17a6a8bb168899e626449771db82dc8575907a78a04201aea3ea7b98832494c2b1543af0f65addeb60630d07544ad03ec7eda8911ca44efc4e62ce94e87c7347baa1fe4708c556f331436968f25e7b2500a24676b6eb0fe14ad84679852db21d1ac8f3860d35991c1b78a5f633bbcfa07f9feba0816970cc27eaba33df5bf53be34aea11c5692be4e454f285fb2651c1abec39d1bb416df2ba3723128bc4011a228e9964e490eb3b7d2cdee83b8519467cf9dcb246b827955d4d76386df54d1d34ba6e577033348e2f32422f1bb
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160762);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/17");

  script_cve_id("CVE-2021-40125");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy93480");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ikev2-dos-g4cmrr7C");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Adaptive Security Appliance Software IKEv2 Site-to-Site VPN Denial of Service (cisco-sa-asaftd-ikev2-dos-g4cmrr7C)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Internet Key Exchange Version 2 (IKEv2) implementation of Cisco Adaptive Security Appliance 
(ASA) Software could allow an authenticated, remote attacker to trigger a denial of service (DoS) condition on an 
affected device. This vulnerability is due to improper control of a resource. An attacker with the ability to spoof
 a trusted IKEv2 site-to-site VPN peer and in possession of valid IKEv2 credentials for that peer could exploit this 
 vulnerability by sending malformed, authenticated IKEv2 messages to an affected device");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ikev2-dos-g4cmrr7C
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c784582");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy93480");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy93480");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40125");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.8', 'fix_ver': '9.8.4.40'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.30'},
  {'min_ver': '9.13', 'fix_ver': '9.14.3.9'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.17'},
  {'min_ver': '9.16', 'fix_ver': '9.16.2'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['ikev2_site_to_site_VPN_peer'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy93480',
  'cmds'     , make_list('show running-config crypto')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
