#TRUSTED 2425d633ae3c00b31c5838ed21b06f4d34a4537099a6ad339ddb26f5665241b084c294d77a578e7a2a8c9a2a090715501645a3bb4e515ee8fcb4be330dcf103d45addc154cabc0e25d56f7e679fa4e19fcd30fc6a1ee51476dba3df90dad73b564c0c86803b0c122bcf0e2644e230f719882b53aa07c203e54994fc711ec9b7fa971259fd84171b3b135d2ae87cfd2d585f54c3df550b4e6550b9325720594bfbd3099417aa00982263b8d7a4b8c2b21d8bf0b939a3f373adb841f64b483b1c6debc017ce85740b3c7fc60273dc11f000d82bd2e442ed793c94ff7127b8089001da46a21ab3b68ccfd9993023e1486a3b983d647f7defac0c1a0f6debf258ffbfedbe4b5998e202b2e800ca87bc8e6e1a25d25bad7df5dfa6083717b9e966c31c51ae2279a7c3db6ce8953887fb4646f63f171292e0f0b661a9029e8e2d4e6416936f92019c8541fe4dcaeba3a29ad30c6514d4425ad237b602cf77bc220f53a21e469801a51a2d82b1da17cd0a7dfee035da2e940b22a5f2bafcfd91f55ec12fb83b8d2db2d50778f8dc2a73fbed54ffa0dd0b49bb3884b069a6aafa1509d35d90ce4c5104e570ee9047910868437847dd2dcfed9935a65df4a48ef0eb721a7b5706fcff942dd4e55d292c0f4772991ec59410f6786ccae44c9ba38d6c01a63f2034f1d1fb32e40ddbc8a21adac471e047d77d3f39338b8f47cce57c05b02c5
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149329);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_cve_id("CVE-2021-1486");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx21265");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-enumeration-64eNnDKy");

  script_name(english:"Cisco SD-WAN vManage HTTP Authentication User Enumeration (cisco-sa-vmanage-enumeration-64eNnDKy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by an information disclosure
vulnerability due to improper handling of HTTP headers. An unauthenticated, remote attacker can exploit this, via HTTP,
to determine which accounts are valid user accounts.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-enumeration-64eNnDKy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4a54375");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx21265");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx21265");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1486");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(203);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.3' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvx21265',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
