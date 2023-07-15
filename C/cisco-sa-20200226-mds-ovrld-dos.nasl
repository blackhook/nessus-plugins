#TRUSTED ae8d02953c894cc00e121a26a004131c3fdc5e84fa0207533128c377ba3cfff0921f54c90c2815ee4547cf0ecc8952ce905d7d3d317563ef118aebaaa1004bca8520fd5de5f8c602ea29ad9a87a55c04d99c1d07a8a217d59308328cad99249e5848b205e2acf7d5d4d39d9bfe75c555ec9ad2e6d6265f289ffb845f4b93f988079fd98d34bdbbb7e379a694f0754d052d878b93946a7c4bb6fac21a096e7e5382a4320eaa8aa44674ef57f3af2fcffd195b67f490c0e64feb3d6ec38345147ad4367eeac8c4cb32efcefd1a6967a14b4e501e027d248be8193fee010d57e1fed1d72586f858259c297ad8b79404a161440a50e23889478a7e257d0f223efb535654a20ffe91e4bdf5047c0411cbaafba48a2ac3ba5dd6a6fa68f8b8c1f0eebb852b62c9e6efc5e71099edd55658b88091a22935ff71f205bfd31b0db80fe746e3d3bb6a930c83298c6edd2f31ce9944db15e9bb866f034e349f70047803401a634013454ed3c27980618b4194b00d83b7d1444ddc75119cd196139580d8e5e05a95a8943f8257e420f51877613f3e287483086f9ff7782e427a21f3053f1cec2fbaabf999bdc09613c47e73c96b1bcf20ced2a80603c3e845b6877aa7675c7c620eee427e5c791c49587234c753895a7c352c68529a05b4314c9ef1aa32095673e485dfc89212c78149e9c89876143fee2c52595595a0581ad606d138832404
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134224);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/04");

  script_cve_id("CVE-2020-3175");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo26707");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-mds-ovrld-dos");
  script_xref(name:"IAVA", value:"2020-A-0087");

  script_name(english:"Cisco MDS 9000 Series Multilayer Switches Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is vulnerable to denial of service (DoS) due to missing patch. (cisco-sa-20200226-mds-ovrld-dos)");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco MDS 9000 Series Multilayer Switch due to 
improper resource usage control. An unauthenticated, remote attacker can exploit this issue, via 
sending traffic to the management interface (mgmt0), to cause the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-mds-ovrld-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68ae0b0c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73749");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo26707");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo26707");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3175");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(664);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ( product_info.device != 'MDS' || product_info.model !~ '^9(?!148)([13][0-9][0-9]|25[0-9])')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.3(1)DY(1)',
  '7.3(1)D1(1)',
  '7.3(0)DY(1)',
  '7.3(0)D1(1)',
  '6.2(9c)',
  '6.2(9b)',
  '6.2(9a)',
  '6.2(9)',
  '6.2(7)',
  '6.2(5b)',
  '6.2(5a)',
  '6.2(5)',
  '6.2(31)',
  '6.2(3)',
  '6.2(29)',
  '6.2(27)',
  '6.2(25)',
  '6.2(23)',
  '6.2(21)',
  '6.2(19)',
  '6.2(17a)',
  '6.2(17)',
  '6.2(15)',
  '6.2(13b)',
  '6.2(13a)',
  '6.2(13)',
  '6.2(11e)',
  '6.2(11d)',
  '6.2(11c)',
  '6.2(11b)',
  '6.2(11)',
  '6.2(1)',
  '5.2(8i)',
  '5.2(8h)',
  '5.2(8g)',
  '5.2(8f)',
  '5.2(8e)',
  '5.2(8d)',
  '5.2(8c)',
  '5.2(8b)',
  '5.2(8a)',
  '5.2(8)',
  '5.2(6b)',
  '5.2(6a)',
  '5.2(6)',
  '5.2(2s)',
  '5.2(2d)',
  '5.2(2a)',
  '5.2(2)',
  '5.2(1)',
  '5.0(8a)',
  '5.0(8)',
  '5.0(7)',
  '5.0(4d)',
  '5.0(4c)',
  '5.0(4b)',
  '5.0(4)',
  '5.0(1b)',
  '5.0(1a)'
);

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvo26707',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info  : product_info, 
  reporting     : reporting, 
  vuln_versions : version_list
);
