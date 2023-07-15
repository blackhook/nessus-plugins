#TRUSTED 835c42812124e5333acb71689646ca42058a8ab9fcc64c9dbdaaeb45df466c1f4e5ea223df772eeb5c23dbd523d38fca3d658da753013100a037c119eef856581e6ba911bd3b53cdcc3cff92661d23a3598abba0b7db20d258b7725d53afa7f94691c1300586d4d4927f0a73146b0ae031589cd3144aaa38dfdb3802716fe869384b0bd29eb022a01e4c1e5e88b4209423955355224e4e0ec87f2b53f0193f37ee1fcdcf75e486e4a1300d59ec89703afc332d812aef3e9fb8cfe5158201437b645f6bede2632ab4f2cf53473aec12e33b9c7075a6f3335faa5613254e5b7b93eeee800bb1e4d3d4e4e108264fff9df3cc4fca8d2ec629b7943a0e21d3c7aed0b6a1877c41dd213f8c07550bef6bab1bf03881f68d90cade543f0927d412d9035972ec84b707f64f5897ec8a8d8822bfcc54b219dbf403934a1c6291e0122c671cd6333623efcc039e7bfcdd72f077a4f4a1aac41320822fc07893a521cfd4dc62ec374c56c028f7affce425e7c3a1d094c4debf53ce407c7ce06bb840c28bf399a029ce6dfbce189bf5758eda2839a1a05f7ffe9065ee5517250fb22819f0a7462155b830847f2f9520d074806acabd768d5de1ef1c4231bab7f67788fae28017899d9a0dc5f2ec00dc816d81d0b580a04372c0d264e161075fb00babe6459a1d0498dc5f57f21e07971e5a53c1117727efa45e5ee0610dc46d00f651c41fa5
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152527);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/17");

  script_cve_id("CVE-2021-1518");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx44278");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fdm-rce-Rx6vVurq");
  script_xref(name:"IAVA", value:"2021-A-0365");

  script_name(english:"Cisco Firepower Device Manager On-Box Software RCE (cisco-sa-fdm-rce-Rx6vVurq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Device Manager (FDM) On-Box software is affected by a
vulnerability in the REST API that allows an authenticated, remote attacker to execute arbitrary code on the underlying
operating system of an affected device. This vulnerability is due to insufficient sanitization of user input on specific
REST API commands. An attacker could exploit this vulnerability by sending a crafted HTTP request to the API subsystem
of an affected device. A successful exploit could allow the attacker to execute arbitrary code on the underlying
operating system. To exploit this vulnerability, an attacker would need valid low-privileged user credentials.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fdm-rce-Rx6vVurq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?883451ed");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx44278");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx44278");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_device_manager_on-box");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_device_manager_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco Firepower Device Manager Web Interface");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');
include('http.inc');

get_kb_item_or_exit("Host/local_checks_enabled");
var port = get_http_port(default:443, embedded:TRUE);
var product_info = cisco::get_product_info(name:'Cisco Firepower Device Manager Web Interface', port:port);

# Strip part after -, not needed here
if ('-' >< product_info.version)
{
  product_info.version = split(product_info.version, sep:'-', keep:FALSE);
  product_info.version = product_info.version[0];
}

var vuln_ranges = [
  {'min_ver' : '6.3',   'fix_ver' : '6.4.0.12'},
  {'min_ver' : '6.4.1', 'fix_ver' : '6.4.4'},
  {'min_ver' : '6.5.0', 'fix_ver' : '6.7.0.2'}
];


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx44278',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
