#TRUSTED 207162db3d02e81145e58bc0edbaf44ceca205d58b737c45c8dce09f4f83cac38f04b49d6e3cdfad30dfdd066c8e3904d70a4bf4cdd9ce1b3328186c00bf3500b80b8505919012dd18b863b3f5b15ffbd41f09a4cb9652aaaffe9281d7056337e13625f2a55d5963692c07bef7f3d0baf5a0eba99ab99aa6949f43dbb5641b4c596ac3308f2002455fd29c41192d91ce9ab21306014892f27112cee206e3c3f789fa66dd088bc6096fdd6454f63667d67ae440684722358ad2bdce28bfdbfe0644ccccc9d273c19901e1fced225e75f19ca9eba12ab0a5cf691ca39e3464a3fdf1850e5a122fce060eac254685b173f68d2ff184193edd91f709de3938755a83673be23e8f51126c0cb2911fbbbf49b78402f7b3376d28b530312aeb6d5f8b06679ed4e63953bf5b7c5d18dc1255a6883d301c69bc2866d0f58f1c1f500c8dd2e9a9de176343bedd9221098076745c73673f7584be188043e8c205ef6609eaf832408721c1cfd2a410905d31b1c46d72258ebcccd16c479f579ef56c56834aba89f29641db6f7f92e471a68748acec3c18594fc54384da19766763b571c985589691f935c2557d3f0f3a01304c8b9e7ce78720914f335c6fc3da8fe517a10c2331331e14a43056343ac15c44fb1426b9d8658f2ef51c1157071cfd19286c70da66b77d0e3e034aa6b3d4002988d4a03ab8a0437be845aa3f0dc5a3fd89ecf221
#TRUST-RSA-SHA256 441dd19e94ae5dc8e5148b21bb5f5391b51d416df639472b89f57242e0ceb97784f13c2ad5cc960f03c21c198fb069d9df30faaf9d55035b14459ade14186501fb95826b844ede55781e2031353ffd890039578055c5b74ff39726421a779d8e69adc8f0c2473749c69068f7de79c20609412c913ecdc9f458c2e5b8dfc98100db961443c346b3baf40cddbe19aa54ca627f7d9b02d49c92a2ce6fde4858e0e17bdf6a704d0a79377911f9ba9c8b0b1d84836325358799280f622e39472cfc9f2ea9d8fbbb2677f89ce40f5a85f0228e61dd61f2e14469edd028bb471987b5dd165399f3203a5c9ee68eac4b872cfa9c4433fc4317793e2596dfdcc51c4182591838d5d4a532b4d97751ce0c31c11de08f98159be9227fba662c794de5c594211f467c4cb101886f0799550e43936b9f013b5aa353dcc445025cf8f22a46749a6be3c96429f37d104450d9d916cc0c00a0e313edaa1c7e989d46a201d8427292a83f7a8fadbe7d3081ae903bca2e4a03f8f7d55858ea5a49c2b3740b57d7a859a4fcca24b9bc5eabed624172e13feafb76c3a9fc5775104c730defd2800b313902b192d64a9ffda69cc3b3b2e88a1d2852dd151eca3d8c47ac3b64eb5239c6ed2d4782d8ddbc57b5aad9689ef8e88ac7d9d469e9491f07c941e924861136821687308445eadf400a3cdf6e753ddfa7103e13fc192811c2e6100df97c40fa90eb
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133722);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-3120");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr14976");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15072");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15073");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15078");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15079");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15082");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15111");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200205-fxnxos-iosxr-cdp-dos");
  script_xref(name:"IAVA", value:"2020-A-0059");
  script_xref(name:"CEA-ID", value:"CEA-2020-0016");

  script_name(english:"Cisco NX-OS Software Cisco Discovery Protocol Denial of Service Vulnerability (cisco-sa-20200205-fxnxos-iosxr-cdp-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is affected by a denial of service vulnerability
within the Cisco Discovery Protocol due to missing a check when processing protocol messages. An unauthenticated,
adjacent attacker can exploit this to cause the device to reboot.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200205-fxnxos-iosxr-cdp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3303b2ba");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr14976");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15072");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15073");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15078");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15079");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15082");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15111");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr14976, CSCvr15072, CSCvr15073, CSCvr15078,
CSCvr15079, CSCvr15082, and CSCvr15111.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^10[0-9][0-9]V")
    cbi = 'CSCvr15078';
  if (product_info.model =~ "^10[0-9][0-9]" && 'SV' >< toupper(product_info.model))
    cbi = 'CSCvr15078';
  if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCvr14976';
    smus['7.0(3)I7(5a)'] = 'CSCvr09175-n9k_ALL-1.0.0';
    smus['7.0(3)I7(6)'] = 'CSCvr09175-n9k_ALL-1.0.0';
    smus['7.0(3)I7(7)'] = 'CSCvr09175-n9k_ALL-1.0.0';
  }
  if (product_info.model =~ "^9[0-9]{3}")
  {
    cbi = 'CSCvr14976, CSCvr15072';
    smus['7.0(3)I7(5a)'] = 'CSCvr09175-n9k_ALL-1.0.0';
    smus['7.0(3)I7(6)'] = 'CSCvr09175-n9k_ALL-1.0.0';
    smus['7.0(3)I7(7)'] = 'CSCvr09175-n9k_ALL-1.0.0';
  }
  if (product_info.model =~ "^(5[56]|60)[0-9][0-9]")
    cbi = 'CSCvr15079';
  if (product_info.model =~ "^70[0-9][0-9]")
  {
    cbi = 'CSCvr15073';
    smus['8.4(1)'] = 'CSCvs27997';
  }
}
else if ('UCS' >< product_info.device)
{
  if (product_info.model =~ "^6[234][0-9][0-9]")
    cbi = 'CSCvr15082, CSCvr15111';
}
else if ('MDS' >< product_info.device)
{
  if (product_info.model =~ "^90[0-9][0-9]")
    cbi = 'CSCvr15073';
}

if (empty_or_null(cbi)) audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '5.0(1a)',
  '5.0(1b)',
  '5.0(4)',
  '5.0(4b)',
  '5.0(4c)',
  '5.0(4d)',
  '5.0(7)',
  '5.0(8)',
  '5.0(8a)',
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
  '6.1(5a)',
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
  '5.2(1)SM3(2.1)',
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
  '5.2(1)SV3(4.1a)',
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
  '6.0(2)A8(11)',
  '6.0(2)A8(11a)',
  '6.0(2)A8(11b)',
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
  '6.0(2)N2(5b)',
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
  '6.1(2)I1(2)',
  '6.1(2)I2(1)',
  '6.1(2)I2(2)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(3)',
  '6.1(2)I2(2b)',
  '6.1(2)I3(1)',
  '6.1(2)I3(2)',
  '6.1(2)I3(3)',
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
  '6.2(23)',
  '6.2(20a)',
  '6.2(25)',
  '6.2(17a)',
  '6.2(22)',
  '6.2(27)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(2)N1(1)',
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(5)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I1(1z)',
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
  '7.0(3)I2(2r)',
  '7.0(3)I2(2s)',
  '7.0(3)I2(2v)',
  '7.0(3)I2(2w)',
  '7.0(3)I2(2x)',
  '7.0(3)I2(2y)',
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
  '7.0(3)I4(1t)',
  '7.0(3)I4(6t)',
  '7.0(3)I4(9)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(3)',
  '7.0(3)I5(3a)',
  '7.0(3)I5(3b)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(3z)',
  '7.0(3)I7(6)',
  '7.0(3)I7(6z)',
  '7.0(3)I7(7)',
  '7.0(3)IX1(2)',
  '7.0(3)IX1(2a)',
  '7.0(3)N1(1)',
  '7.0(4)N1(1)',
  '7.0(4)N1(1a)',
  '7.0(5)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(6)N1(1)',
  '7.0(6)N1(4s)',
  '7.0(6)N1(3s)',
  '7.0(6)N1(2s)',
  '7.0(7)N1(1)',
  '7.0(7)N1(1b)',
  '7.0(7)N1(1a)',
  '7.0(8)N1(1)',
  '7.0(8)N1(1a)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1b)',
  '7.1(0)N1(1)',
  '7.1(1)N1(1)',
  '7.1(1)N1(1a)',
  '7.1(2)N1(1)',
  '7.1(2)N1(1a)',
  '7.1(3)N1(1)',
  '7.1(3)N1(2)',
  '7.1(3)N1(5)',
  '7.1(3)N1(4)',
  '7.1(3)N1(3)',
  '7.1(3)N1(2a)',
  '7.1(4)N1(1)',
  '7.1(4)N1(1d)',
  '7.1(4)N1(1c)',
  '7.1(4)N1(1a)',
  '7.1(5)N1(1)',
  '7.1(5)N1(1b)',
  '7.2(0)D1(1)',
  '7.2(0)N1(1)',
  '7.2(1)D1(1)',
  '7.2(1)N1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(2)D1(3)',
  '7.2(2)D1(4)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)DY(1)',
  '7.3(0)N1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(1)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(1d)',
  '7.3(2)N1(1)',
  '7.3(2)N1(1b)',
  '7.3(2)N1(1c)',
  '7.3(3)N1(1)',
  '8.0(1)',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.1(1a)',
  '8.1(1b)',
  '8.2(1)',
  '8.2(2)',
  '8.2(3)',
  '8.2(4)',
  '8.3(1)',
  '8.3(2)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.2(2v)',
  '7.3(4)N1(1)',
  '7.3(4)N1(1a)',
  '7.3(3)D1(1)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IC4(4)',
  '7.0(3)IM3(1)',
  '7.0(3)IM3(2)',
  '7.0(3)IM3(2a)',
  '7.0(3)IM3(2b)',
  '7.0(3)IM3(3)',
  '7.0(3)IM7(2)',
  '7.3(4)D1(1)',
  '7.3(5)N1(1)',
  '5.2(1)SK3(1.1)',
  '5.2(1)SK3(2.1)',
  '5.2(1)SK3(2.2)',
  '5.2(1)SK3(2.2b)',
  '5.2(1)SK3(2.1a)',
  '5.2(1)SV5(1.1)',
  '5.2(1)SV5(1.2)',
  '8.4(1)',
  '9.3(1)',
  '9.3(1z)'
);

workarounds = make_list(CISCO_WORKAROUNDS['nxos_cdp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info.version,
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE,
  smus:smus
);

