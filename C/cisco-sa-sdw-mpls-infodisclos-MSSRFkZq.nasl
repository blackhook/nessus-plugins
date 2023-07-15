#TRUSTED 0e0ee467777342056241914bc03dd2450c6c46571308bd6447891d09b391a03c1a08a4b7b573b3a305e30e37e76a03d6b0b2dad8936a5640c0eace32e45a04c68573499d436d1f7f2f31b05b9f77637803b757bb7b1290c42012ab264a4394c6475ba92cd4c7c6efa7cc8fdea2256afdb03cd73acb03dd760f81078ade613807b7bb8b49777a2aff7dedf6ee96348013e60667ea1a37b7591bc4a23044764f641b9dd8d53ee07a4246468db34ea7bb94bcbd6ebd39175ad85ad72b2b4a60876d404d73d67075c1f2ee65124c81edd4ae7bdf66a4df331ee25a69a391419f8349974d961313c2953d82cdd0b60e73f301f0aa56d97b8cddfa13d2c6c116426d1a7c7de94730ea590b08d8f0b32dcf8be23cf0c8688fe068aa8131711c8656921f02209a67a95fe3e2fc8185b645bfd625e16265a880d7a67eb8da560f8046feb2b873954bec742940ff587401f6594def2b14f64a442fc7b6ae947ec5d9a31a430906aab495942df3bef7e84b12b137d46b2124a763eba6ad4760867697a2b525f36ab8613931ffd45a19727454f35bc630bee2ee3baec3f33680871318a02cff466c6afe7e6947a5f919104f47a1c8a8c65b03109218f72ac6cde37c725b8c74a29e8e7aebb1bda0d09508dfff5ff3f7f5064fb53ed505a1e7c9f98c1706e002eeece83ae2c1c9662ffb8ecf238a18d6e01895c715a0ec2e47a473698d184f68
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151915);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1614");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28403");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdw-mpls-infodisclos-MSSRFkZq");
  script_xref(name:"IAVA", value:"2021-A-0351-S");

  script_name(english:"Cisco SD-WAN Software Information Disclosure (cisco-sa-sdw-mpls-infodisclos-MSSRFkZq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdw-mpls-infodisclos-MSSRFkZq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6a12dcc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu28403");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(126);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
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


var vuln_ranges = [
  { 'min_ver' : '18.4', 'fix_ver' : '18.4.6' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.3' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.2' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

var version_list = make_list(
  '18.4.302.0',
  '18.4.303.0',
  '19.2.097',
  '19.2.099'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu28403',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
