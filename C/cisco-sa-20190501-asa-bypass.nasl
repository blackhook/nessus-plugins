#TRUSTED 02a9b3cf2a391701d2b45054d3c4f8a103312bfcd0f3436de96e959fcb6c03480fac92fc6984baf710a28ff0464af508b67b9e11765d9370c92c6bd6da7086d26aa017087e62fce327c428b0741ab0c2c64621e9e7cdbf3fa6e26d79aa5061fef42813459b2e3d8b66a6a360249ad64061021c65b60dda22babd92c212043d253bc8c650ea67b67fa91bf3b0a61408c71576a44f720339aaac4ef6279ae81e19094aba5e3d3d0a93dc3c04666446e6699aa5f630dd157eb2983a1d4aa93a58f0f5c801361f6f0ffa2e1be79ca1107c040e8f0330dfb5d1c1d6209226b704290f308f075d2470ff09dcd1559fda8187c0d18c6dfa788fd260ca42a0669324775add0194430024a221a77bd78a23dca1807bbedec512c14cc16dd99d0174017ee2fbe7ef8971d4f6ae38a8ab63ecea853a38066b79f6704728ba0312c0735382c53f58455a3f4d2a74f621cfc8f7a5581fcffb4885bc70c499515451e248028f3a1df838383388366d72dabc45e3a223399859df7737628e024efead247cd7d11d82250a5436048fc96211d8bbd00cde167a1c8394885f3600f04e56cce7cd66b272e4374849eeb82e4293dfa02034829eb857b94bead79bb949cd9f8c819b06119f1b718235ef25387a2bfc5caf292167363b0f5888eafd4c2ad37da7d14685cbdef029cf3765bce8c6490d0b26f6c2717217b3b87eca166adf90be17df8059dd
#
# (C) Tenable Network Security, Inc. 
#

include('compat.inc');

if (description)
{
  script_id(137234);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/10");

  script_cve_id("CVE-2019-1695");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm75358");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asa-ftd-bypass");

  script_name(english:"Cisco Adaptive Security Appliance Layer 2 Filtering Bypass (cisco-sa-20190501-asa-ftd-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance (ASA) Software is affected by 
a vulnerability in the detection engine due to improper filtering of Ethernet frames. An unauthenticated, 
adjacent attacker can exploit this, by sending crafted packets to the management interface of an affected 
device, in order to bypass the Layer 2 (L2) filters and send data directly to the kernel.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-ftd-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f0a37bb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm75358");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm75358");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '9.8.2',   'fix_ver' : '9.8.4'},
  {'min_ver' : '9.9',   'fix_ver' : '9.9.2.50'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.17'}
];

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvm75358'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
); 