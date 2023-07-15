#TRUSTED 4cf68b5afa77ed093e184e93bcc748f47db3e891de3fd29cabcaf35ae4a896c336f1fb2db8e64e27547ad0b7b9fa34e08a951dbc3b8df3208ed079823f1b22a4565276c7933e4a17eac5e0e5c74f18b83c494ddbf87a213513561617ea1ee414a3887f2729ba8ebf14da2c5cdaa1877d36c3d7c4d04a510a91c51d6119fe02e5e1161e5587266ff2e679e3301ec59b96b657799c9ecff7ea1aa32ac3841e25123349a494e59470cc5e5a21345263e1d0e766839654a50be164fb0cf83265776779a2e02109eb8e328da1a4b92cb6f5e0cf4d3088d9b1baaa2665ef7cdc77e131a0c6f1c0a50f452e88daa5f1e79baaceb2a6601767d4210af719a96965fed16227cafe16aacddc5160db7bf76bc03dec2a0ddb25c759dc5a169ff3e688ac158b21bf150343ca4c703f886b94af5737254906c717cf4bc8d9840d875617ea30c18375b3c9e184d484677e167f884ca647811ba4388aa1dd9faafe2517283b9bcbc84874827b498db223567703e624c44969163ccaa79d64099fee3123d0860aea9ddd2f65e6f9ddf41d0a1696a25ac71527c458c14a345364f124af1843bba2eec0752a0cb40e0efb903ae0d4f4af4089917321d60fd66d6faedb41e3045d20adb0e9a7464585e82d0404da306c98229ee606e78eb9fa79795e49f341781d5da009c19304db94c0b93fccea1d81f718febe2bcef99c3147990913bb41e3ddcd16
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153204);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/22");

  script_cve_id("CVE-2021-34771");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy33646");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-infodisc-CjLdGMc5");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software Unauthorized Information Disclosure (cisco-sa-iosxr-infodisc-CjLdGMc5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by an information disclosure vulnerability that allows
an authenticated, local attacker to view more information than their privileges allow. This vulnerability is due to
insufficient application of restrictions during the execution of a specific command. An attacker could exploit this
vulnerability by running a specific command. A successful exploit could allow the attacker to view sensitive
configuration information that their privileges might not otherwise allow them to access.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-infodisc-CjLdGMc5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f1500d0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74637");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy33646");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy33646");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34771");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(201);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
 {'min_ver': '0.0', 'fix_ver': '7.3.2'},
 {'min_ver': '7.4', 'fix_ver': '7.4.1'}
];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvy33646',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
