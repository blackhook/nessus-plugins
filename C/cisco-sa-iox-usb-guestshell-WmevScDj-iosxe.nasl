#TRUSTED 530dc98ae36175b473a4ea288ab61773f56509a9f76a1e501bd7f796275abcee9eb7b850623489c4c5d707da09b2d5638cbbd8b316249f6e673f3e487f1286454a99f793e21f3201e3b23af7b9143896fbc9b47764e8c8debf140f53d371942e042164682cb823c51446ceb85e5232b4ed506b12b470c2304cc074e6035291047badde22e5764dabd027117514b5bc5e2c34033a7c67e5c49cf4fb99eee0982a31af35eea05660461632acf285eeb33e658ace7ad463918f4a007ce232fff32f434cc9a381ba1e5ff729e1aad0143cf2f47ace8d3ee178ad1ae07a018e0d3482de628eabc21511242332a936cf21635215cbbf2795838a9650aad9abeb2044504388428fc3a04a0caa5954b112ea74ec2f66a86f625b949b5944f7c5ecc03513ac5edad5fcf794e4168853ddcfc0796f65a37856503ebf70297eb277ec4254693904e5d37020cdc8e100afe202a1e51d503658695aba9324d48d95eb318b05f1273a9374cd61fe41b9f9012cda0e3726f463bd01d7fccb09a935aca42dc09d1a1b4c0b61d4b416dc4a4bdfb98a1d8c469029a49dba5c59cf5ad50f97a2592789bdab9191c978cedaea9759764bb16523f79e99594e3d0b81ae54e83cbb18e645d62f8701f29f163faecb23ff020f3efd58ad0a4ca94dbc4e249238de771c0b06a97da997b10111c13708c0698e0a6c5c8c80112e6ece9cadb3b1b0b7d899b426
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143490);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3396");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr50406");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-usb-guestshell-WmevScDj");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software IOx Guest Shell USB SSD Namespace Protection Privilege Escalation (cisco-sa-iox-usb-guestshell-WmevScDj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a privilege escalation vulnerability due to a
vulnerability in the file system on the pluggable USB 3.0 Solid State Drive (SSD). An attacker could exploit this
vulnerability by removing the USB 3.0 SSD, modifying or deleting files on the USB 3.0 SSD by using another device,
and then reinserting the USB 3.0 SSD on the original device. A successful exploit could allow the attacker to remove
container protections and perform file actions outside the namespace of the container with root privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-usb-guestshell-WmevScDj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94de82a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr50406");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr50406");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3396");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info['model'];
device_model = get_kb_item('Host/Cisco/device_model');

if (('catalyst' >!< tolower(model) && 'cat' >!< device_model) || model !~ "9[35][0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.8.1',
  '16.8.1a',
  '16.8.1c',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.10.1',
  '16.10.1a',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a'
);

workarounds = make_list(CISCO_WORKAROUNDS['iox_guest_shell'], CISCO_WORKAROUNDS['show_inventory_usbflash']);
reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr50406'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  require_all_workarounds:true,
  reporting:reporting,
  vuln_versions:vuln_versions
);
