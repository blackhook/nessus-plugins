#TRUSTED 3c4ba93529f2bb483792cfee2e16f2c7882f93c7a976f3eb014321a3e9ab80307f3d134be5df226b9e7f29b9235f003e30cd9ee72cd6d2344c94e6b84c825a43191ce1a7b2382864ad50308b90de7a5e80578f8eb94b0f5dadfbd53ddb884c0f7fca69e3d394d1ac6855211bb098b1f70a276f62159b82f1325504156c0018eaeaeb9dc489cc8312b0902b9fff71141491ad7f79e2e7d7910d435b712c6a415a7a44e8c352a12f510e92a1f310caefe2aca1b8e98a27b644fe91509b4071763150fcf468a86561e90e7cde5c3b915cb33f63ddd21bc007f32c507fa25c928f8074d0e85a5cc64cd17b603660f3238120c100ea995ffd883a58c4f63c74b169ae3d3452c1327e8ff525959508d9ac9d5d8064da4ac1c2c0edaafd8c462945a6aca555fa1c72be88a54cddb1ee24488a67afaeefe0c24939744518a35597a42072dbfb6537a9b268d98cfeac670f12a4289b5725dddf54c5590d074781680940562e659ca1b1a383864968974a65f9f88631ebab85c7117871ff02f7582527db3dfcc4479f1fcbd5652d8ed69990b897f01634fdd8d066d2f09247644cb3f89461bace782e413777239c002fadfaad3de8738c1512aa8bb04624428acfbb70be2ba7a40cc1b07a742d8606351f12865ed32be0ea6dbd32ab786fa3b1bd0ddb8ea9b2d3a3106fb1f0c592fe5b8580bf4af4add0140c18280d418eb26fdac3fcbc6e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154726);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/07");

  script_cve_id("CVE-2021-1573", "CVE-2021-34704", "CVE-2021-40118");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy36910");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy58278");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy89144");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asafdt-webvpn-dos-KSqJAKPA");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services Multiple DoS (cisco-sa-asafdt-webvpn-dos-KSqJAKPA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by multiple vulnerabilities.

  - Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software
    and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to
    trigger a denial of service (DoS) condition. These vulnerabilities are due to improper input validation
    when parsing HTTPS requests. An attacker could exploit these vulnerabilities by sending a malicious HTTPS
    request to an affected device. A successful exploit could allow the attacker to cause the device to
    reload, resulting in a DoS condition. (CVE-2021-40118)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asafdt-webvpn-dos-KSqJAKPA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47a2b253");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy36910");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy58278");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy89144");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvy36910, CSCvy58278, CSCvy89144");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40118");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 234, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.40'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.29'},
  {'min_ver': '9.13', 'fix_ver': '9.14.3.9'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.17'},
  {'min_ver': '9.16', 'fix_ver': '9.16.2.3'}
];

var workarounds = make_list(
  CISCO_WORKAROUNDS['ssl_vpn'],
  CISCO_WORKAROUNDS['anyconnect_client_services']
);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy36910, CSCvy58278, CSCvy89144',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
  