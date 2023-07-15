#TRUSTED 1af235d42893d8f630bd8a4fd4240d4a4c86065d3f4f6706335c769c49e977cc7b426160e54408707da4c8c5c0a1e393a6cc32c371924676d201ef37338ebf5238057b4bd929fd95fcc72157e14c15e166c71bb4887cd1b75ae83d5464ca45b86e97e57f59c3af4a43fab0356b2107054ec96a634996895ad0ced02b192dd93e5df0f05155f28616426ee3fe83c7d37be1bc26a0aceec323c2f8030dc7b2d904c870796fb94a8339e0606563fcb9daef94667e23fa8e4f199232e27a3c4d86139946f1d153bedc39a050a15f7510832c9f535e26da2f6ebd28ba480394bbc58f88f4f4a9044d372f46670e1c7526cdb5b6e5d6595bdfbd57c52b60cdda44804e443b7284b6592be4f83ea40d423764c82de9d50d9dd6658162f4d2ae8c40de00327c08196366d09373b3b0b768fa424cabfed643f5ecaced549acceb05e95620aa49cbf6f7df170a2257bbbac5b7cfff9ad3e9c765f75f7bb21d24352f0919286c76377f0400349a730b4ecb611e3e479cb3e0f97a139382652045841bee303e3147b30e1b682fb5dd15643c35f9ba8c17f1926079f60443310bb9a8203fabbb532e033f19738c022d076feca09b5985c53b6a8f803e313fdcd8312548379b8867addf87ec54ce1e1dcb822573f9abda69d1ba87f2d621ac2c28a94f230e352e8dfdcdffcad92f6f8510c44651d1afe8e76fe516dcc2676e176fcf2eac7ec2e7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132719);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/28");

  script_cve_id("CVE-2019-1728");
  script_bugtraq_id(108391);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96578");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20223");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96579");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96577");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96580");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96583");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-conf-bypass");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Secure Configuration Bypass (cisco-sa-20190515-nxos-conf-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a configuration bypass vulnerability due
to a lack of proper validation of system files when the persistent configuration information is read from the file
system. An authenticated, local attacker can exploit this, by authenticating to the device and overwriting the
persistent configuration storage with malicious executable files. An exploit allows the attacker to run arbitrary
commands at system startup with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-conf-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a24f9c8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96578");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20223");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96579");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96577");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96580");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96583");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi96578, CSCvh20223, CSCvi96579, CSCvi96577,
CSCvi96580, and CSCvi96583.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if (('MDS' >< product_info['device']) && (product_info['model'] =~ '^90[0-9][0-9]'))
  cbi = 'CSCvi96578';
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^(30|90)[0-9][0-9]')
    cbi = 'CSCvh20223';
  else if (product_info['model'] =~ '^35[0-9][0-9]')
    cbi = 'CSCvi96579';
  else if (product_info['model'] =~ '^(36|95)[0-9][0-9]')
    cbi = 'CSCvi96577';
  else if (product_info['model'] =~ '^(55|56|60)[0-9][0-9]')
    cbi = 'CSCvi96580';
  else if (product_info['model'] =~ '^(70|77)[0-9][0-9]')
    cbi = 'CSCvi96578';
}
else if (('UCS' >< product_info['device']) && (product_info['model'] =~ '^6[23][0-9][0-9]'))
  cbi = 'CSCvi96583';

if (isnull(cbi)) audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '4.1(2)',
  '4.1(3)',
  '4.1(4)',
  '4.1(5)',
  '5.0(2a)',
  '5.0(3)',
  '5.0(5)',
  '5.0(1a)',
  '5.0(1b)',
  '5.0(4)',
  '5.0(4b)',
  '5.0(4c)',
  '5.0(4d)',
  '5.0(7)',
  '5.0(8)',
  '5.0(8a)',
  '5.0(2)',
  '4.2(2a)',
  '4.2(3)',
  '4.2(4)',
  '4.2(6)',
  '4.2(8)',
  '5.1(1)',
  '5.1(1a)',
  '5.1(3)',
  '5.1(4)',
  '5.1(5)',
  '5.1(6)',
  '5.1(2)',
  '5.2(1)',
  '5.2(3a)',
  '5.2(4)',
  '5.2(5)',
  '5.2(7)',
  '5.2(9)',
  '5.2(3)',
  '5.2(9a)',
  '5.2(2)',
  '5.2(2a)',
  '5.2(2d)',
  '5.2(2s)',
  '5.2(6)',
  '5.2(6b)',
  '5.2(8)',
  '5.2(8a)',
  '5.2(6a)',
  '5.2(8b)',
  '5.2(8c)',
  '5.2(8d)',
  '5.2(8e)',
  '5.2(8f)',
  '5.2(8g)',
  '5.2(8h)',
  '5.2(8i)',
  '6.1(1)',
  '6.1(2)',
  '6.1(3)',
  '6.1(4)',
  '6.1(4a)',
  '6.1(5)',
  '6.1(3)S5',
  '6.1(3)S6',
  '6.1(5a)',
  '4.0(0)N1(1a)',
  '4.0(0)N1(2)',
  '4.0(0)N1(2a)',
  '4.0(1a)N1(1)',
  '4.0(1a)N1(1a)',
  '4.0(1a)N2(1)',
  '4.0(1a)N2(1a)',
  '4.1(2)E1(1)',
  '4.1(2)E1(1b)',
  '4.1(2)E1(1d)',
  '4.1(2)E1(1e)',
  '4.1(2)E1(1f)',
  '4.1(2)E1(1g)',
  '4.1(2)E1(1h)',
  '4.1(2)E1(1i)',
  '4.1(2)E1(1j)',
  '4.1(2)E1(1m)',
  '4.1(2)E1(1c)',
  '4.1(2)E1(1n)',
  '4.1(2)E1(1k)',
  '4.1(2)E1(1o)',
  '4.1(2)E1(1q)',
  '4.1(2)E1(1l)',
  '4.1(2)E1(1p)',
  '4.1(3)N1(1)',
  '4.1(3)N1(1a)',
  '4.1(3)N2(1)',
  '4.1(3)N2(1a)',
  '4.2(1)N1(1)',
  '4.2(1)N2(1)',
  '4.2(1)N2(1a)',
  '4.2(1)SV1(4)',
  '4.2(1)SV1(4a)',
  '4.2(1)SV1(4b)',
  '4.2(1)SV1(5.1)',
  '4.2(1)SV1(5.1a)',
  '4.2(1)SV1(5.2)',
  '4.2(1)SV1(5.2b)',
  '4.2(1)SV2(1.1)',
  '4.2(1)SV2(1.1a)',
  '4.2(1)SV2(2.1)',
  '4.2(1)SV2(2.1a)',
  '4.2(1)SV2(2.2)',
  '4.2(1)SV2(2.3)',
  '5.0(2)N1(1)',
  '5.0(2)N2(1)',
  '5.0(2)N2(1a)',
  '5.0(3)A1(1)',
  '5.0(3)A1(2)',
  '5.0(3)A1(2a)',
  '5.0(3)N1(1c)',
  '5.0(3)N1(1)',
  '5.0(3)N1(1a)',
  '5.0(3)N1(1b)',
  '5.0(3)N2(1)',
  '5.0(3)N2(2)',
  '5.0(3)N2(2a)',
  '5.0(3)N2(2b)',
  '5.0(3)U1(1)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(2)',
  '5.0(3)U1(2a)',
  '5.0(3)U1(1c)',
  '5.0(3)U2(1)',
  '5.0(3)U2(2)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2d)',
  '5.0(3)U3(1)',
  '5.0(3)U3(2)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2b)',
  '5.0(3)U4(1)',
  '5.0(3)U5(1)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1j)',
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
  '5.2(1)N1(8a)',
  '5.2(1)N1(8)',
  '5.2(1)N1(8b)',
  '5.2(1)N1(9)',
  '5.2(1)N1(9a)',
  '5.2(1)N1(9b)',
  '5.2(1)SM1(5.1)',
  '5.2(1)SM1(5.2)',
  '5.2(1)SM1(5.2a)',
  '5.2(1)SM1(5.2b)',
  '5.2(1)SM1(5.2c)',
  '5.2(1)SM3(1.1)',
  '5.2(1)SM3(1.1a)',
  '5.2(1)SM3(1.1b)',
  '5.2(1)SM3(1.1c)',
  '5.2(1)SV3(1.4)',
  '5.2(1)SV3(1.1)',
  '5.2(1)SV3(1.3)',
  '5.2(1)SV3(1.5a)',
  '5.2(1)SV3(1.5b)',
  '5.2(1)SV3(1.6)',
  '5.2(1)SV3(1.10)',
  '5.2(1)SV3(1.15)',
  '5.2(1)SV3(2.1)',
  '5.2(1)SV3(2.5)',
  '5.2(1)SV3(2.8)',
  '5.2(1)SV3(3.1)',
  '5.2(1)SV3(1.2)',
  '5.2(1)SV3(1.4b)',
  '5.2(1)SV3(3.15)',
  '5.2(1)SV3(4.1)',
  '5.2(1)SV3(1.3a)',
  '5.2(1)SV3(1.3b)',
  '5.2(1)SV3(1.3c)',
  '5.2(9)N1(1)',
  '6.0(1)',
  '6.0(2)',
  '6.0(3)',
  '6.0(4)',
  '6.0(2)A1(1)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(2d)',
  '6.0(2)A3(1)',
  '6.0(2)A3(2)',
  '6.0(2)A3(4)',
  '6.0(2)A4(1)',
  '6.0(2)A4(2)',
  '6.0(2)A4(3)',
  '6.0(2)A4(4)',
  '6.0(2)A4(5)',
  '6.0(2)A4(6)',
  '6.0(2)A6(1)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(2)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(3)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(4)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(5)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(6)',
  '6.0(2)A6(7)',
  '6.0(2)A6(8)',
  '6.0(2)A7(1)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(2a)',
  '6.0(2)A8(1)',
  '6.0(2)A8(2)',
  '6.0(2)A8(3)',
  '6.0(2)A8(4)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(5)',
  '6.0(2)A8(6)',
  '6.0(2)A8(7)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(8)',
  '6.0(2)A8(9)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
  '6.0(2)N1(1)',
  '6.0(2)N1(2)',
  '6.0(2)N1(2a)',
  '6.0(2)N1(1a)',
  '6.0(2)N2(1)',
  '6.0(2)N2(1b)',
  '6.0(2)N2(2)',
  '6.0(2)N2(3)',
  '6.0(2)N2(4)',
  '6.0(2)N2(5)',
  '6.0(2)N2(5a)',
  '6.0(2)N2(6)',
  '6.0(2)N2(7)',
  '6.0(2)U1(1)',
  '6.0(2)U1(2)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(3)',
  '6.0(2)U1(4)',
  '6.0(2)U2(1)',
  '6.0(2)U2(2)',
  '6.0(2)U2(3)',
  '6.0(2)U2(4)',
  '6.0(2)U2(5)',
  '6.0(2)U2(6)',
  '6.0(2)U3(1)',
  '6.0(2)U3(2)',
  '6.0(2)U3(3)',
  '6.0(2)U3(4)',
  '6.0(2)U3(5)',
  '6.0(2)U3(6)',
  '6.0(2)U3(7)',
  '6.0(2)U3(8)',
  '6.0(2)U3(9)',
  '6.0(2)U4(1)',
  '6.0(2)U4(2)',
  '6.0(2)U4(3)',
  '6.0(2)U4(4)',
  '6.0(2)U5(1)',
  '6.0(2)U5(2)',
  '6.0(2)U5(3)',
  '6.0(2)U5(4)',
  '6.0(2)U6(1)',
  '6.0(2)U6(2)',
  '6.0(2)U6(3)',
  '6.0(2)U6(4)',
  '6.0(2)U6(5)',
  '6.0(2)U6(6)',
  '6.0(2)U6(7)',
  '6.0(2)U6(8)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(9)',
  '6.0(2)U6(10)',
  '6.1(2)I1(3)',
  '6.1(2)I1(1)',
  '6.1(2)I1(2)',
  '6.1(2)I2(1)',
  '6.1(2)I2(2)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(3)',
  '6.1(2)I2(2b)',
  '6.1(2)I3(1)',
  '6.1(2)I3(2)',
  '6.1(2)I3(3)',
  '6.1(2)I3(3.78)',
  '6.1(2)I3(4)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(5)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5b)',
  '6.1(2)I3(3b)',
  '6.2(2)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '6.2(10)',
  '6.2(12)',
  '6.2(18)',
  '6.2(16)',
  '6.2(14b)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(6a)',
  '6.2(20)',
  '6.2(1)',
  '6.2(3)',
  '6.2(5)',
  '6.2(5a)',
  '6.2(5b)',
  '6.2(7)',
  '6.2(9)',
  '6.2(9a)',
  '6.2(9b)',
  '6.2(9c)',
  '6.2(11)',
  '6.2(11b)',
  '6.2(11c)',
  '6.2(11d)',
  '6.2(11e)',
  '6.2(13)',
  '6.2(13a)',
  '6.2(13b)',
  '6.2(15)',
  '6.2(17)',
  '6.2(19)',
  '6.2(21)',
  '6.2(20a)',
  '7.0(3)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(1)N1(3)',
  '7.0(2)I2(2c)',
  '7.0(2)N1(1)',
  '7.0(2)N1(1a)',
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I3(1)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8z)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.3(1)D1(1B)',
  '7.3(1)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)N1(0.1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1(0.296)',
  '7.3(2)N1(1)',
  '7.3(3)N1(1)',
  '8.0(1)S2',
  '8.0(1)',
  '8.1(1)',
  '8.1(1a)',
  '8.2(1)',
  '8.2(2)',
  '7.3(3)D1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
