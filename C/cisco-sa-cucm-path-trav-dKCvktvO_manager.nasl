#TRUSTED 299a64b2d051a79828386b57e58ebe28b55c59f23f13884205eccaf136f4fe4ff024eeb1a10d91fe887d7348de2a333844842da46fe719363232025777de58e15a80503e3365d501edf3fc66ddc02ffba5388501be0feab030eaf4452ebe587f5881fc3a4db96fb8ce568d57ba6025cd9e3e1e332e66b918bc82909ea19e38fc8bccd6b058bb8821fd6ca42db342226aad04c04d0d8a76a1184acfb104f8ba44330d1c31cdad7acda56521c663acb6c1f72262c473fd6464ee29326b325edee5f26601ad1436e431f1384eb9134789573953eb17e7dd4b4ac7d31aabcda352b881f945eba6beadd605025a8a9b0dc9b9e0c8693ef19e818d02e6dd02ecce7f2b3590d6ac6d252ef63b305d27129c83d2cd05d15a882eea4d41dc55674406df28c02745cb10b4d70c928f85914b3c8e2c3c0b1878a573abab71fa7fcdee8938de9dd6265dc523a9f8195cd14b492e3db59fab6fb9071b44c6570fffe6fcdcf2be3be3bf6493d0c6d961fe56687abc69cfc554ae6b331e9f5fffec46cba28e53794154b9dd183c32fdce729b11c55c6b2cd03080baf327ba6743498659b106786c0961274de91fa6f1bf39c0d726dc95726bcac3f49644980557c21477134649783481ed054ae6faa61fbb7406a69efbe4adb3cefc64fc6d0ed2d667ef6656f0bf9c2a765f7f6efd7ad12638866ecc6185daca06073e79a72ec7a7fa874e8e359f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154929);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-34701");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy64877");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy89690");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy89691");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-path-trav-dKCvktvO");
  script_xref(name:"IAVA", value:"2021-A-0530");

  script_name(english:"Cisco Unified Communications Manager Path Traversal (cisco-sa-cucm-path-trav-dKCvktvO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Self Care Portal of Cisco Unified Communications Manager (Unified CM) is 
affected by a path traversal vulnerability in its web-based management interface due to a failure to properly
validate user input. An authenticated, remote attacker can exploit this, by sending a URI that contains path 
traversal characters, to disclose the contents of files located outside of the server's restricted path.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-path-trav-dKCvktvO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d746fdc8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy64877");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy89690");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy89691");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Unified Communications Manager version 14SU1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34701");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# http://www.nessus.org/u?dd376e97
var vuln_ranges = [{ 'min_ver' : '0.0',  'fix_ver' : '14.0.1.11900'}];

var reporting = make_array(
  'port', 0,
  'severity', SECURITY_WARNING,
  'version', product_info['display_version'],
  'bug_id', 'CSCvy64877, CSCvy89690, CSCvy89691',
  'fix', '14SU1',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
