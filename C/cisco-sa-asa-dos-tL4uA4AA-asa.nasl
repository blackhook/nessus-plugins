#TRUSTED 9ddbcca0f2ac78215378c4f6813a63a1b4f8bfd3a75b1d3413bff3b2036e135a9d99b2f469fd0f606186b50619be68d45a8e8898a6c967bb1e44d7efab5eb8ef4cc3950e74311acb83f025b8c45090735ab7b066ffa682c8acec8c6dcf4852753f05a9d2d088af20a801a882ac7a7174ddbff43e60acf608d0c2d98f62c73374a2ffa2fd130a1e5ff9f2d8a5f25607419eb71eb94a9bc31d58aa1309b8df6d4abe362820a6f0a996833a5b74decfe4f146a4faba5d37f74a050f42262109d548a4715d242abb476dcbf67cdbfe0b249ccc11ecc217c0c4f9abd9caeb81b9eebcaf752637b8892d75dd25e20aca284d09a1012db0e8b82ff2857b894b4980c74b5dd4fe5ca93d6dca17dade56b54bf0b0868f5c070eba283df84b4a802396273116ffdc0945aa27ba6cd2dbb03572931074310af0861fc2da07dc95f3939664a163ffcfc05d601eba4337838ed8713a553f89bac43e0b197e2d8fb2e0a6f884ecb687a221dddc5f722965bfff4e4518658d042f1a25845b50448e632ae0bf0b0571cbab3349c5b728a9a5caea53a07a3181b50c375dfba685556bc95c6fb5476e0ec8d982bf7833c6bf7dff52fabe4f7e99afa8b3e0ec1055e53405c171a3d88567074bb789dbcd2dcb3fb602b0478a18c1b431c6b11a272639909902c0f34defcfd0667ee116de541695d97617c444b89ad1c7e6944f934f2bc56b9883ac0919
#TRUST-RSA-SHA256 ae2dd9dd5503b87aefce5b53d544a664dbb8b4047e3fdcf0d65d918cec957ff89414c72c7f4a02c036e039e9c5544975f5b83f7e5ace56e4defea1996da0d0e57db4c0491c98e15ac7f7a9f414f361ba5708841c7816065a395dfd66c07f02b9a22a0ab4ab3b63f1f7dc4c6ebf21b4f914529bee596f401967c7c696181ef96de464190666a05394ea2b2d9a5a16d580c983614b49783e9bbd3d68b74f1f22c68b0416a258b2f2c89c91e72da6e670f411c8588f33ed1a6f9f09509e3a535cc36b424b10608fa4c843991784a87185815781802a98567371b574a8f107185755f4fc04144f9f6ffae19d3095ffdce400e1637a3f330e12f15ff17c0e73e2ea72b3565731792351809a86427153737a69f1ad3975a89e16815cd3243ab50fb8f115d4585058adde3978b4c783c1c3a9d9342230636cb825cd1032e3c3c51c23894facb143815d207f856963d4ef58b26448f774db6e09d059e7294aee505cf925a9e06e1c6b482bb60b4bfe960851357a441cc5ad52a2bac307b2da92c282308a95066526ae07d51e4b76e882ae58d0b364184420449a6cc93348f6d3f96e0eeebe66167fe3560ce14e140b9f7ce42d722eeeec8f8f076551823e43dd6d171382378f71ad22dfb0cbfa260f860f1db162774edbcfe5aca83cd9c98364b4441e53e77535df6ca1c574593dabc13878168ca5331084b4e4e4f8d282bd3d11af103d
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161869);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20715");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa04461");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-dos-tL4uA4AA");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Remote Access SSL VPN DoS (cisco-sa-asa-dos-tL4uA4AA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the remote access SSL VPN features of Cisco Adaptive Security Appliance (ASA) Software 
could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected 
device.

This vulnerability is due to improper validation of errors that are logged as a result of client connections 
that are made using remote access VPN. An attacker could exploit this vulnerability by sending crafted requests 
to an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-dos-tL4uA4AA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3087735a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa04461");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa04461");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.16', 'fix_ver': '9.16.2.11'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ssl_vpn']
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa04461',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
