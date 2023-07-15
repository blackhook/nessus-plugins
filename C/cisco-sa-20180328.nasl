#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135922);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0155");
  script_bugtraq_id(103565);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc40729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-bfd");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS and IOS XE Software Denial of Service Vulnerability (cisco-sa-20180328-bfd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the Bidirectional Forwarding Detection (BFD) offload implementation of
Cisco Catalyst 4500 Series Switches and Cisco Catalyst 4500-X Series Switches due to insufficient error handling when the
BFD header in a BFD packet is incomplete. An unauthenticated, remote attacker can exploit this issue by sending crafted
BFD message to or across an affected switch. If the attacker is succesful then this could allow the attacker to trigger
a reload of the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-bfd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c66d9346");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc40729");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvc40729");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0155");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(388);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/show_ver");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

if (product_info['model'] !~ "4(500(E|-X)?)|(9(00M|48E))")
  audit(AUDIT_DEVICE_NOT_VULN, 'The Model ' + product_info['model']);


vuln_versions = [
  '15.1SG',
  '15.1(1)SG',
  '15.1(2)SG',
  '15.1(1)SG1',
  '15.1(1)SG2',
  '15.1(2)SG1',
  '15.1(2)SG2',
  '15.1(2)SG3',
  '15.1(2)SG4',
  '15.1(2)SG5',
  '15.1(2)SG6',
  '15.1(2)SG7',
  '15.1(2)SG8',
  '15.2E',
  '15.2(1)E',
  '15.2(2)E',
  '15.2(1)E1',
  '15.2(3)E',
  '15.2(1)E3',
  '15.2(2)E1',
  '15.2(2b)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(2)E2',
  '15.2(2)E3',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(4)E1',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(4)E2',
  '15.2(3)E4',
  '15.2(4)E3',
  '15.2(2)E6',
  '15.2(2)E5a',
  '15.2(3)E5',
  '15.2(2)E5b',
  '15.2(4)E4',
  '15.2(2)E7',
  '15.2(4)E5',
  '15.2(2)E7b',
  '15.2(4)E5a',
  '15.2(4s)E2'
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['bfd'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_versions     : vuln_versions
);
