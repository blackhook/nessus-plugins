#TRUSTED 55c88d6a45d596a7748a018e938a12e662fe73bf0f54b6cb071de225fb551536ac4dd218c95ac9c6b8071e50cef983345a8c0d564d823b2dc79512925be62c2294243d960bd4f338d5672943437ed25d83e8bc831e9cea10a39aea128fc629af2219a9419c2bd9fdf3647a094b9ae09baf6ed2d9cb3fa5f8b6edee657b2760bbad563e4659f39f80bca87dbc76009d9bfa63e9dc63084226f6174619bf099db48ed0a5e84c2d7f175a36acff2bc130dbc8d9e55877b53ac683b71c9a358b967f4d638e45ae1a1ff6d6645de60ac2a630ffe92dfed66d78d447588a5891d1d79a85a09ec1e85668f9d600e6a0316489e28fd7f503fb1513ffa73edd233729fa802e0c9625ac0da699800f3f9047e0469c25d2f5673472e92bfe4a3da0ec2eb0c1fc3adf06c241b7bec70ea2a539c859e8b65cec97e76c4810ca56e1e9445b6e9de3d6fcd5d80c129f4797e162266eea8b037e8105037bbb82c8d8b30bf2691cb132a7c26b85e9906fd40531df45a58dc1a46679adde81a6594df598aafcef6d22707fb7c5a79aaaa03508dd7fda1eb4eae76d094e40c44f1d42cb2a7f075e40698c5e0a2c9b1c45a56fca918d3914a368bb18cc8309936b9d07c46af3e719171ef04b234c372c014499f2aa1792a5afd16543ff509220e65a341bb32734ac2dd31b6c78b9e5c6a870d5be310baeb3cb57a91299bc6bb2fb69329a0ef75b2c7eb7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139035);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3331");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50861");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50862");
  script_xref(name:"CISCO-SA", value:"cisco-sa-code-exec-wH3BNFb");
  script_xref(name:"IAVA", value:"2020-A-0331");

  script_name(english:"Cisco Small Business RV Series Arbitrary Code Execution (cisco-sa-code-exec-wH3BNFb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is 
affected by an arbitrary code execution vulnerability due to improper input validation. 
An unauthenticated remote attacker can exploit this, via maliciously crafted requests, 
to execute arbitrary code with root privilage. 
 
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-code-exec-wH3BNFb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f49a149b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50861");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50862");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs50861, CSCvs50862");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3331");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');
get_kb_item_or_exit('Cisco/Small_Business_Router/Model');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');
models = make_list(product_info.model);

if (product_info.model =~ '^RV110W($|[^0-9])')
# RV110W affected version < 1.2.2.8
vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '1.2.2.8' }
];
# RV215W affected version < 1.3.1.7
else if (product_info.model =~ '^RV215W($|[^0-9])')
{
  vuln_ranges = [ 
    { 'min_ver' : '0', 'fix_ver' : '1.3.1.7' } 
  ];
}
else 
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series Router');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50861, CSCvs50862',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:models
);
