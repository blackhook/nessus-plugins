#TRUSTED aeb6f2f77838407e0ea867f57ef8805570a2de1388f6e28964115175603cc077d0160ad2dad9e060fc0f5f6440b47c844aae0c042098b4e9113235afb2edf336509432cbfa302b702fe73ddd6d83efbe2040d5c24920afff578a6923cc2da58387bec59cacfa55698407427813527d4a0f7085a9fcf166cc8ddfc06861ea6c9f41c9e0aaf5af6e19415488a1e6ce7b92855ed76c3337fa7f2b070792d8c43153edbdd4fec3f097284cbaa9a97269dfbd6fe754325b5c2b57be31fdeba58e7ecc334083abd859d11f5e871a17f2d206dfd7054d0b9df7ac4f3a999e665fd7ebe1939f05c4aac404e753e1915c6f82dbc9e33deab207ae5ad7e8ffb38f8c6457948da81c2bf27d620c07c7b686f01c862ae58a8100d299dda50788a69eb36416c2bd0974720f21804f60daa20cef6cc23e7e30f615a5fed18debfcb3e7fe72e4c16c046de238e51dc1637d1c8c6f3f2cbc9a5dbb0bebfd079c6c4c213c8cbdaa304034e7d9ed71d7bcc6a8649eb57441696a62742d998d5738fa06f2b64aecb04124d6db9dd029fdf2ac80a20dca7b36c67ab51e2a06f8605a1a4e5064117af8bc12624601d6e7cad9f86cf5a9e60f7482ceb4662d8119d3d3d0427bc578a0333301e2096d44d72759fc963a19188e9eb42dc58ffd4808af88bbeaceb5b7442b2e4841e3e0d347bc9e629124b8f7801b02a692a65ee448b9aecc51c5467adcb2a0

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124196);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0177");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd80714");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-ipv4");

  script_name(english:"Cisco IOS XE Software for Cisco Catalyst Switches IPv4 Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by a vulnerability in the IP Version 4 (IPv4) processing code
of Cisco IOS XE Software running on Cisco Catalyst 3850 and
Cisco Catalyst 3650 Series Switches could allow an unauthenticated,
remote attacker to cause high CPU utilization, traceback messages,
or a reload of an affected device that leads to a denial of service
(DoS) condition.

The vulnerability is due to incorrect processing
of certain IPv4 packets. An attacker could exploit this vulnerability
by sending specific IPv4 packets to an IPv4 address on an affected
device. A successful exploit could allow the attacker to cause high
CPU utilization, traceback messages, or a reload of the affected
device that leads to a DoS condition. If the switch does not reboot
when under attack, it would require manual intervention to reload
the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-ipv4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a61dfafd");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd80714
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00b9b268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvd80714");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");
device_model = get_kb_item_or_exit('Host/Cisco/device_model');
model = get_kb_item('Host/Cisco/IOS-XE/Model');

if( device_model !~ 'cat' || (model !~ '3850' && model !~ '3650')) audit(AUDIT_HOST_NOT, "affected");

version_list=make_list(
'3.18.3bSP',
'16.1.1',
'16.1.2',
'16.1.3',
'16.2.1',
'16.2.2',
'16.3.1',
'16.3.2',
'16.3.3',
'16.3.1a',
'16.4.1',
'16.4.2',
'16.4.3',
'16.5.1',
'16.5.1b'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd80714'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list);
