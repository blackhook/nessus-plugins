#TRUSTED 93a8f3429c1573d5d117ba811930b0f98aee3191455d9689d6a86fe1aa2ebd2ba15cf8138a0a7b048b74d0f55cbde494c123aaf4e85d04b5b595b9bdc4e845826794b63e12d6fcf76f33820a3832a7ca52ab33c3fdd62d0a7a36559bda712e71e74a7de0218a2048f3cff00e42e047d42950be2bc9dcdd83603e775c5cbc64dd131e0d48331b24de40d64cb04f22340af176fdb2d4bbffb7182d7412a6b47772394d5417248af5270b880344b43280aa0ea8756784e5ea7c218830878e946f30d11beb0a850ba9241174608c97a510c4b2a8ed985318eb1b14cb50c3e8ca5ae0a239817917e16e3a39f93d752d373316b65489f3bda9aadc25207bd333ea35039ba7917ca52ddb2a009c9e331b4e0de9e482af51eba589bc99d8c52d2ee427709af8e823c54e2c8dd89c8fc8d3f4eb1e30cb75428ff58463ba3799830ecc01f1778704fe8c17d6d1a4e90863746be8e0b48f74ffd77a7b19ce63b90c53fd5161a8d1ee6eb1b41c44792c36e9ea9890e1b9756c5743abde4ae8cfe1194ad60c4ba583271d955815192ca736588a78218596647f83c619a93d84486784490b1a892b99a2156ff52359a1b91342968089f2ed662a225d518e9829000f396eac68414f2182c440cc4f7d0cfed1544fbe0aa8f4c290e7b368c95af35a2aca973cd11798086963124ef1265292d11599149f59e060646ba5559c02329310d96139e9f8
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159717);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/03");

  script_cve_id("CVE-2022-20717");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt55609");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vedge-dos-jerVm4bB");

  script_name(english:"Cisco SD-WAN vEdge Routers DoS (cisco-sa-sdwan-vedge-dos-jerVm4bB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the NETCONF process of Cisco SD-WAN vEdge Routers could allow an authenticated, local
    attacker to cause an affected device to run out of memory, resulting in a denial of service (DoS)
    condition. This vulnerability is due to insufficient memory management when an affected device receives
    large amounts of traffic. An attacker could exploit this vulnerability by sending malicious traffic to an
    affected device. A successful exploit could allow the attacker to cause the device to crash, resulting in
    a DoS condition. (CVE-2022-20717)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vedge-dos-jerVm4bB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d82e79f2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt55609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt55609");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20717");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(789);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_1000_router");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_100_router");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_2000_router");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_5000_router");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vedge[^0-9]*100([^0-9]|$)|vedge[^0-9]*1000([^0-9]|$)|vedge[^0-9]*2000([^0-9]|$)|vedge[^0-9]*5000([^0-9]|$)")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.1' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt55609',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
