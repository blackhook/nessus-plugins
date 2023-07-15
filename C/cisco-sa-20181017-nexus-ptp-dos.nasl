#TRUSTED 99494169e0753e1b7c10bb8a1bac6863f87250fada05ea229d94079a196b5ffab9daf9530f677317b51a6d55876b980d3f1d2b17546a4264e75d927c463e89a37d9a97012e42b3421e9cf7bd3e79d39533b4fdcecf4927f259563d90b9051ec9ecc72ccc0e137190caca261a72bb561290cbb502d4656cef42400c56643f11a84c41887f7931e3da214d47f5f6e30eeaffdfe3dea6e72814b4d8099614dcb05ad9eff8a8ca819c4804589a10a0a7b7aa57164a9c664bcbc6fbed98fadf3d8c9a5b1c56e562f962d69e3c69f6184514d5829c9874d8ec0c2a41782322f93777901fd3356bbfc752876f0197e1339cf58de9dd4c52f012da1cf03c5f3affc37dce28e4ccadc714858882ef495e791b15f8248962c765277bfb7e52afbdc8696d096e01544b5a0cd798831873ccb61b670f07836ff57ef50eed1171ae9f61e3e4eb3ef5ca4d9e69dfa4edcd778e6ac860f55c26eaba4a2f0934376e2dc15f1291ab28daea8f53b8c5436eeaffa8e445bd47209b51ef088faa48d67df3be1e12f306918d3304f4b991f28abd868a610f54af2e233755ac987ee7d9cd2af50f8bbbd33f308cbb78ebcf41bcc4c90a2dd81eed30ccf1e7a7194a8e5700faf3c5496949c51de2e73180a00f9d55e0e3918f0e5aeafcc56402973919efb3f4c0f87b4618336e5d135531a833a50765c9cff14527c590aecdce66b1a0dbcdad6ead73e594
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128877);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_cve_id("CVE-2018-0378");
  script_bugtraq_id(105669);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg21830");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-nexus-ptp-dos");

  script_name(english:"Cisco NX-OS Precision Time Protocol (PTP) Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco NX-OS Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is affected
by a denial of service (DoS) vulnerability which exists in its Precision Time Protocol (PTP) implementation due to a 
lack of protection against PTP frame flood attacks. An unauthenticated, remote attacker can exploit this issue, by 
sending large streams of malicious PTP traffic to the device, to cause the system to stop responding. 

Please see the included Cisco BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-nexus-ptp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e46fc38e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg21830");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvg21830.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0378");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

device = get_kb_item_or_exit('Host/Cisco/NX-OS/Device');
model = get_kb_item_or_exit('Host/Cisco/NX-OS/Model');
version = get_kb_item_or_exit('Host/Cisco/NX-OS/Version');

if ('Nexus' >!< device || model !~ '^5[56][0-9]{2}|6[0-9]{3}')
  audit(AUDIT_HOST_NOT, 'an affected device and/or model');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

version_list = make_list(
  '6.0(2)N1(2)',
  '6.0(2)N1(2a)',
  '6.0(2)N2(1)',
  '6.0(2)N2(1b)',
  '6.0(2)N2(2)',
  '6.0(2)N2(3)',
  '6.0(2)N2(4)',
  '6.0(2)N2(5)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(2)N1(1)',
  '7.0(3)N1(1)',
  '7.0(6)N1(1)',
  '7.1(1)N1(1)',
  '6.0(2)N2(5a)',
  '6.0(2)N2(6)',
  '6.0(2)N2(7)',
  '7.0(4)N1(1)',
  '7.0(5)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(7)N1(1)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1b)',
  '7.1(2)N1(1)',
  '7.1(3)N1(1)',
  '7.2(0)N1(1)',
  '7.2(1)N1(1)',
  '4.2(1)N1(1)',
  '4.2(1)N2(1)',
  '4.2(1)N2(1a)',
  '5.0(2)N1(1)',
  '5.0(2)N2(1)',
  '5.0(2)N2(1a)',
  '5.0(3)N1(1)',
  '5.0(3)N1(1a)',
  '5.0(3)N1(1b)',
  '5.0(3)N1(1c)',
  '5.0(3)N2(1)',
  '5.0(3)N2(2)',
  '5.0(3)N2(2a)',
  '5.0(3)N2(2b)',
  '5.1(3)N1(1)',
  '5.1(3)N1(1a)',
  '5.1(3)N2(1)',
  '5.1(3)N2(1a)',
  '5.1(3)N2(1b)',
  '5.1(3)N2(1c)',
  '5.2(1)N1(1)',
  '5.2(1)N1(1a)',
  '5.2(1)N1(1b)',
  '5.2(1)N1(2)',
  '5.2(1)N1(2a)',
  '5.2(1)N1(3)',
  '5.2(1)N1(4)',
  '5.2(1)N1(5)',
  '5.2(1)N1(6)',
  '5.2(1)N1(7)',
  '5.2(1)N1(8)',
  '5.2(1)N1(8a)',
  '5.2(1)N1(8b)',
  '5.2(1)N1(9)',
  '5.2(1)N1(9a)',
  '5.2(1)N1(9b)',
  '6.0(2)N1(1)',
  '7.0(8)N1(1)',
  '7.1(0)N1(1)',
  '7.1(3)N1(2)',
  '7.1(4)N1(1)',
  '7.1(5)N1(1)',
  '7.3(0)N1(1)',
  '7.3(1)N1(1)',
  '7.3(2)N1(1)',
  '7.3(1)N1(1)',
  '7.3(2)N1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(0)N1(1)',
  '7.2(1)N1(1)',
  '7.2(0)N1(1)',
  '7.1(5)N1(1)',
  '7.1(4)N1(1d)',
  '7.1(4)N1(1c)',
  '7.1(4)N1(1a)',
  '7.1(4)N1(1)',
  '7.1(3)N1(5)',
  '7.1(3)N1(4)',
  '7.1(3)N1(3)',
  '7.1(3)N1(2a)',
  '7.1(3)N1(2)',
  '7.1(3)N1(1b)',
  '7.1(3)N1(1)',
  '7.1(2)N1(1a)',
  '7.1(2)N1(1)',
  '7.1(1)N1(1a)',
  '7.1(1)N1(1)',
  '7.1(0)N1(2)',
  '7.1(0)N1(1b)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1)',
  '7.0(8)N1(1a)',
  '7.0(8)N1(1)',
  '7.0(7)N1(1b)',
  '7.0(7)N1(1a)',
  '7.0(7)N1(1)',
  '7.0(6)N1(4s)',
  '7.0(6)N1(3s)',
  '7.0(6)N1(2s)',
  '7.0(6)N1(1c)',
  '7.0(6)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(5)N1(1)',
  '7.0(4)N1(1a)',
  '7.0(4)N1(1)',
  '7.0(3)N1(1)',
  '7.0(2)N1(1a)',
  '7.0(2)N1(1)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '4.2(1)N1(1)',
  '4.2(1)N2(1)',
  '4.2(1)N2(1a)',
  '5.0(2)N1(1)',
  '5.0(2)N2(1)',
  '5.0(2)N2(1a)',
  '5.0(3)N1(1)',
  '5.0(3)N1(1a)',
  '5.0(3)N1(1b)',
  '5.0(3)N1(1c)',
  '5.0(3)N2(1)',
  '5.0(3)N2(2)',
  '5.0(3)N2(2a)',
  '5.0(3)N2(2b)',
  '5.1(3)N1(1)',
  '5.1(3)N1(1a)',
  '5.1(3)N2(1)',
  '5.1(3)N2(1a)',
  '5.1(3)N2(1b)',
  '5.1(3)N2(1c)',
  '5.2(1)N1(1)',
  '5.2(1)N1(1a)',
  '5.2(1)N1(1b)',
  '5.2(1)N1(2)',
  '5.2(1)N1(2a)',
  '5.2(1)N1(3)',
  '5.2(1)N1(4)',
  '5.2(1)N1(5)',
  '5.2(1)N1(6)',
  '5.2(1)N1(7)',
  '5.2(1)N1(8)',
  '5.2(1)N1(8a)',
  '5.2(1)N1(8b)',
  '5.2(1)N1(9)',
  '5.2(1)N1(9a)',
  '5.2(1)N1(9b)',
  '6.0(2)N1(1)',
  '6.0(2)N1(2)',
  '6.0(2)N1(2a)',
  '6.0(2)N2(1)',
  '6.0(2)N2(1b)',
  '6.0(2)N2(2)',
  '6.0(2)N2(3)',
  '6.0(2)N2(4)',
  '6.0(2)N2(5)',
  '6.0(2)N2(5a)',
  '6.0(2)N2(6)',
  '6.0(2)N2(7)',
  '7.1(4)N1(1e)'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ptp_clock'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg21830',
  'cmds'     , make_list('show ptp clock')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
