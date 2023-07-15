#TRUSTED 3770f3ee243251322c05d59e009c24208e46dff0632834217278ce1aa4b5a490b53f2484dd4280c5fbeb00977270fdd8564c089b82a965b744efd4c6bc6669c8fd2b6797eba673f2f8e7f1832e2dbf122f47ad3d5d859fdaa5e2a6a630ccb16f18de690d491286e3f5220accfab5b98a994a1b0b0cf4113559586070400ae79001b0b6dd8b6e96844c0130523845be399fee0a0f14395404233377ee376f7eb2557ef4b2714c19dd09d448c0dcf54bb58db08c144b3237cfefb4401ac7788a28210b3fad8f95c6d78bbd8cefd545f385b9437b625574c3bdf080ea944b57a06b7ee4a70a8cdb80a08ac11e8318ff92f8eeedc17449e514cba824754ddb31a0513e7dd944fed1b88c3a9cfb08c5df1a2f0b4ca28696186c982491a3d513cdc54ef8866b626c0a498d0a3b7e0970d94c29a8b7215219d3c51708cc4598e5a09e412732baf6d23d961afe19f2a16c0df85cb3c51788f5ffa7dc6f5a72a93a7c5fd62dc6e1f7f5ffe21e0249cdac475ba559ae56e76923cd54ae27829f860763c2c3a15988915a6d499ab9b32d0fb05e92723dd26c20ee83679553b4b3f996837e4e1254634a8bf1a468fd119e81598887a6c5895a3223483204b1e6055279266bd1ff5b3207cadd03bd76bd7bdeda5a46e9984dc84ad66cb22834495f56bc8ef0791ece951cddebcd5ed8cf8a540ba4aa7ed67332959cac704cc4695f246c615adc
#TRUST-RSA-SHA256 874caf51368a23042eba71f8d7117aa1d89ae9b0060f8f54295211a8d17e35fe72d10adf106c5d6c301863ca16805956d2afebafee9dae4d64e6f9e34f278ad1e72b0a085efedaaa49979a26e690554f9fb06a5c02e573452dca3441fdcc0bc50b17ac61917bcce1b9e692ebab4ea04cb4744eb6b3fa0488176a0a89992a69335fa091c0272954bb440e18f9d20dc74053dfcb18d8250956a53b88dfc5175132a0e78b50418ba1d7e6be2e5ffc1f4f3ee79488463f75b4462f56d4d3bae84c36f6d4b7df06b424c9c448edb8b124e1a90a66770c94f324dd251efb6d7450f5b4f4cf7d4c12f3dd3e8c248718369e3f8347639d5ea95ecabfc3e055b42d725f79092772e6000519615a4f53fc6234a736f4dd1b126c51e83d490a841a50a0e426c0c49b3ee468f40e276d53f82d8290ac3655fa052865a0347d85b7814f47da7f99efd764ca6eb7ab9f68cda127c96c4bf66a9268bc714516334c51ec1beb1bdb59d7b837ec0a649053fcf4b312c0841f23820fd96a95a2bb97fd04410de04a82c7060b639658155ce2a13bac25ffbf0e0089889d80ce134185fbeffb417bead843d45586e3cc41d86c1c513b77752f0603e1300146b187d82e5586d292b80ce6bc6d3b2549b7cee7ae297719e32b3a6ca1a335487f2372c3efd63ece28f2ac20b99621e74b0de99d6f3cd9269d76648e6f029fc9782c334d068098e0fd3601b1
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161500);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20745");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz70595");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asafdt-webvpn-dos-tzPSYern");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services Interface DoS (cisco-sa-asafdt-webvpn-dos-tzPSYern)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web services interface for remote access VPN features of Cisco Adaptive Security 
Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause a denial of service 
(DoS) condition.

This vulnerability is due to improper input validation when parsing HTTPS requests. An attacker could exploit
 this vulnerability by sending a crafted HTTPS request to an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
 number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asafdt-webvpn-dos-tzPSYern
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebbed325");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz70595");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz70595");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/25");

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
  {'min_ver': '0.0', 'fix_ver': '9.8.4.44'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.35'},
  {'min_ver': '9.13', 'fix_ver': '9.14.3.13'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.21'},
  {'min_ver': '9.16', 'fix_ver': '9.16.2.7'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
   WORKAROUND_CONFIG['anyconnect_client_services'],
   WORKAROUND_CONFIG['ssl_vpn']
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz70595',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
