#TRUSTED 039f3dfd500c114c21bb911e257e5fe700a6210df7467191c4985a53075a0dc2e8d11819028741a25d30dd35c86fdbe2ecc313b28742d02550b5f675f2b012a6e42de3080ebaedfdbcd6f9a79438f0c6eef3ad7dfd86ee342f8029a309832ef36260b16ff57f0677498e081049cb712e0ee8fd01c0ccfd67f0d3728fef5fce4957bf0e1193e5409f8453984c4affa6342cc81d27f8973f64f183d1c0fe825cdc34d0deafb4f7db7fd0858c781ebb21957c6c68fdb4c546b6a2337e18d6a24ec0be8a86df5f4a153e4e79b7c104db848bf85ef771c9bf26faed3ad5cabff21bc1b212a0e4a1c25afca816129204d14ed58d6a9c8c98b4c511831de490acb6fca2b9d024232aeb0202bebcaa7315ae959c986c71ee389e2325903cfb005d874dcc766b09bf2c52e95d91ebc58d14bda55eed93add56ef72f76b851e73a97c4ac7a753afc9b4ba5d7b241b52cb3c72326c07ecb72600a1927a6a8177d5f52dbde5119e6069b1b823f8016921ef30a3e3e44f587c6efd1d4195b2eafa0caefad773f6d055211790740d1e68eb18f0f1943c306ebde16df1abdd47fa9cb6d700b12da48d07b5fa8ed8d1ed5dc99d2ff55850b613b17a349287dd92db7d43924caf25532ea9749769d266b1add60f905c9a0711ca42be55248c4ab31ca9d71c33cf4f209a6696f55904cb7722f7bc9e4905b6e77bd659702640ecec51fcf8a8fbd0e64
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129732);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12653");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj91021");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-rawtcp-dos");

  script_name(english:"Cisco IOS XE Software Raw Socket Transport Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability. The vulnerability in
the Raw Socket Transport feature of Cisco IOS XE Software could allow an unauthenticated, remote attacker to trigger
a reload of an affected device, resulting in a denial of service (DoS) condition. The vulnerability is due to improper
parsing of Raw Socket Transport payloads. An attacker could exploit this vulnerability by establishing a TCP session
and then sending a malicious TCP segment via IPv4 to an affected device. This cannot be exploited via IPv6, as the Raw
Socket Transport feature does not support IPv6 as a network layer protocol. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-rawtcp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cd2a48a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj91021");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj91021");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info['model']);
if (model !~ 'ASR90[0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '3.2.0JA',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['raw_socket_tcp_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj91021',
  'cmds'     , make_list('show raw-socket tcp detail | include Socket|listening')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only: TRUE
);
