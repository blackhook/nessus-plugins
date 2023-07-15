#TRUSTED 663e0fec5d8b6c5284bd25282908db31a67b30b8d5b53f2d8c662b1577f258063cd5ea3c47a99830c482e7d7fe8a3296ed708c2f201b94479f3de7ccee37938cf8b8620e4023ae6877954a1408544e227a88826f31757ea88b75e0807bcdcd1da37ab55da662f13aa0b8cf1e4c02fbd82d54d1b97b335a5661c2a5f9f5f53564823c0ae0035a73de6a35ec009a76681f52865896ad5a82e33576edfadbab526c7c90ab4cc8e3ac11ab2846e5df27e49276fb0d1faa2721a84a1dbb776b8740f10ca3f42f48959900c6c44e3f6786c0985385144e5b88f7356a2aaca22e1d1b4c71a03feb7f3e00870e4d2ba399e9a25444c45a1645750299f01c194fb74c2d2216c69fe6a9bd7cc667db4e6057b50e78a8b83f044b758857e3cfda3c3ad8857933b6a054d139a85b002535c48d9b3a1d71a9cf02c81e2b962365159e21a30cc4039a00fbbd8bb3f70ffb87946662d31465fc7dbf1cb8b0c1d6b86038a1e3a137c847d10ad47dcb1e77672f7d71cb78a9f5b12f1423e37fa34d8816bd4677efb4a42ba5cd31baa135199f2cacde22a5ae2858140654fe03ec820094d0b1c429c3eae3f9f20fb2776b1fc38e410d9119e484b6fa7fe666e6fb45308c56e67b65d15abde4e069ad60a26a1453788c2b8c49b1cece635cc575be96d9e0fbb23a44f5ccf2cf64bff633a766ec3dd27293e6e0c7471400fb3ac33c1e541bfa29e4cc2d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128683);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1962");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva64492");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj59058");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk70625");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk70631");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk70632");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk70633");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-nxos-fsip-dos");
  script_xref(name:"IAVA", value:"2019-A-0317");

  script_name(english:"Cisco NX-OS Software Fabric Services over IP Denial of Service Vulnerability (CVE-2019-1962)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the Cisco Fabric Services component of Cisco NX-OS Software due to
to insufficient validation of TCP packets when processed by the Cisco Fabric Services over IP (CFSoIP) feature. An
unauthenticated, remote attacker can exploit this issue, via y sending a malicious Cisco Fabric Services TCP packet
to an affected device, to cause the process crashes, resulting in a device reload and a DoS condition.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-nxos-fsip-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77f177d5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva64492");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj59058");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk70625");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk70631");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk70632");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk70633");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCve51688, CSCvh76126, CSCvj00412, and CSCvj00416");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1962");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
if (('MDS' >< product_info['device']) && (product_info['model'] =~ '^90[0-9][0-9]')) cbi = "CSCva64492";
else if (('UCS' >< product_info['device']) && (product_info['model'] =~ '^6[23][0-9][0-9]')) cbi = "CSCvk70633";
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^35[0-9][0-9]') cbi = 'CSCvk70631';
  else if (product_info['model'] =~ '^(55|56|60)[0-9][0-9]') cbi = 'CSCvk70632';
  else if (product_info['model'] =~ '^(30|90)[0-9][0-9]') cbi = 'CSCvj59058';
  else if (product_info['model'] =~ '^7[07][0-9][0-9]') cbi = 'CSCva64492';
  else if (product_info['model'] =~ '^(36|95)[0-9][0-9]') cbi = 'CSCvk70625';
}
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
'5.0(2)N2(1a)',
'5.0(3)A1(1)',
'5.0(3)A1(2)',
'5.0(3)A1(2a)',
'5.0(3)N1(1)',
'5.0(3)N1(1a)',
'5.0(3)N1(1b)',
'5.0(3)N1(1c)',
'5.0(3)N2(1)',
'5.0(3)N2(2)',
'5.0(3)N2(2a)',
'5.0(3)N2(2b)',
'5.0(3)U1(1)',
'5.0(3)U1(1a)',
'5.0(3)U1(1b)',
'5.0(3)U1(1c)',
'5.0(3)U1(2)',
'5.0(3)U1(2a)',
'5.0(3)U2(1)',
'5.0(3)U2(2)',
'5.0(3)U2(2c)',
'5.0(3)U2(2d)',
'5.0(3)U3(1)',
'5.0(3)U3(2)',
'5.0(3)U3(2a)',
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
'5.0(4b)',
'5.0(4c)',
'5.0(4d)',
'5.0(7)',
'5.0(8)',
'5.0(8a)',
'5.1(3)N1(1)',
'5.1(3)N1(1a)',
'5.1(3)N2(1)',
'5.1(3)N2(1a)',
'5.1(3)N2(1b)',
'5.1(3)N2(1c)',
'5.2(1)',
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
'5.2(2s)',
'5.2(3)',
'5.2(3a)',
'5.2(4)',
'5.2(5)',
'5.2(6)',
'5.2(6a)',
'5.2(6b)',
'5.2(7)',
'5.2(8)',
'5.2(8a)',
'5.2(8b)',
'5.2(8c)',
'5.2(8d)',
'5.2(8e)',
'5.2(8f)',
'5.2(8g)',
'5.2(8h)',
'5.2(8i)',
'5.2(9)',
'5.2(9a)',
'6.0(1)',
'6.0(2)',
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
'6.0(2)A6(1a)',
'6.0(2)A6(2a)',
'6.0(2)A6(3a)',
'6.0(2)A6(4a)',
'6.0(2)A6(5a)',
'6.0(2)A6(5b)',
'6.0(2)A6(6)',
'6.0(2)A6(7)',
'6.0(2)A6(8)',
'6.0(2)A7(1a)',
'6.0(2)A7(2)',
'6.0(2)A7(2a)',
'6.0(2)A8(2)',
'6.0(2)A8(3)',
'6.0(2)A8(4a)',
'6.0(2)A8(5)',
'6.0(2)A8(6)',
'6.0(2)A8(7)',
'6.0(2)A8(7a)',
'6.0(2)A8(7b)',
'6.0(2)A8(8)',
'6.0(2)A8(9)',
'6.0(2)N1(1)',
'6.0(2)N1(1a)',
'6.0(2)N1(2)',
'6.0(2)N1(2a)',
'6.0(2)N2(1)',
'6.0(2)N2(1b)',
'6.0(2)N2(2)',
'6.0(2)N2(3)',
'6.0(2)N2(4)',
'6.0(2)N2(5)',
'6.0(2)N2(5a)',
'6.0(2)N2(5b)',
'6.0(2)N2(6)',
'6.0(2)N2(7)',
'6.0(2)U1(1)',
'6.0(2)U1(1a)',
'6.0(2)U1(2)',
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
'6.0(2)U6(10)',
'6.0(2)U6(5a)',
'6.0(2)U6(5b)',
'6.0(2)U6(5c)',
'6.0(2)U6(6)',
'6.0(2)U6(7)',
'6.0(2)U6(8)',
'6.0(2)U6(9)',
'6.0(3)',
'6.0(4)',
'6.1(1)',
'6.1(2)',
'6.1(2)I1(2)',
'6.1(2)I1(3)',
'6.1(2)I2(1)',
'6.1(2)I2(2)',
'6.1(2)I2(2a)',
'6.1(2)I2(2b)',
'6.1(2)I2(3)',
'6.1(2)I3(1)',
'6.1(2)I3(2)',
'6.1(2)I3(3)',
'6.1(2)I3(3a)',
'6.1(2)I3(4)',
'6.1(2)I3(4a)',
'6.1(2)I3(4b)',
'6.1(2)I3(4c)',
'6.1(2)I3(4d)',
'6.1(2)I3(4e)',
'6.1(2)I3(5)',
'6.1(2)I3(5b)',
'6.1(3)',
'6.1(4)',
'6.1(4a)',
'6.1(5)',
'6.2(1)',
'6.2(10)',
'6.2(11)',
'6.2(11b)',
'6.2(11c)',
'6.2(11d)',
'6.2(11e)',
'6.2(12)',
'6.2(13)',
'6.2(13a)',
'6.2(13b)',
'6.2(14)',
'6.2(14a)',
'6.2(14b)',
'6.2(15)',
'6.2(16)',
'6.2(17)',
'6.2(17a)',
'6.2(18)',
'6.2(19)',
'6.2(2)',
'6.2(20)',
'6.2(20a)',
'6.2(21)',
'6.2(23)',
'6.2(2a)',
'6.2(3)',
'6.2(5)',
'6.2(5a)',
'6.2(5b)',
'6.2(6)',
'6.2(6a)',
'6.2(6b)',
'6.2(7)',
'6.2(8)',
'6.2(8a)',
'6.2(8b)',
'6.2(9)',
'6.2(9a)',
'6.2(9b)',
'6.2(9c)',
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
'7.0(3)I1(1)',
'7.0(3)I1(1a)',
'7.0(3)I1(1b)',
'7.0(3)I1(1z)',
'7.0(3)I1(2)',
'7.0(3)I1(3)',
'7.0(3)I1(3a)',
'7.0(3)I1(3b)',
'7.0(3)I2(1a)',
'7.0(3)I2(2)',
'7.0(3)I2(2a)',
'7.0(3)I2(2b)',
'7.0(3)I2(2c)',
'7.0(3)I2(2d)',
'7.0(3)I2(2e)',
'7.0(3)I2(2r)',
'7.0(3)I2(2s)',
'7.0(3)I2(2v)',
'7.0(3)I2(2w)',
'7.0(3)I2(2x)',
'7.0(3)I2(2y)',
'7.0(3)I2(3)',
'7.0(3)I2(4)',
'7.0(3)I2(5)',
'7.0(3)I3(1)',
'7.0(3)I4(1)',
'7.0(3)I4(1t)',
'7.0(3)I4(2)',
'7.0(3)I4(3)',
'7.0(3)I4(4)',
'7.0(3)I4(5)',
'7.0(3)I4(6)',
'7.0(3)I4(6t)',
'7.0(3)I4(7)',
'7.0(3)I4(8)',
'7.0(3)I4(8a)',
'7.0(3)I4(8b)',
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
'7.0(3)I7(3z)',
'7.0(3)IA7(1)',
'7.0(3)IA7(2)',
'7.0(3)IC4(4)',
'7.0(3)IM3(1)',
'7.0(3)IM3(2)',
'7.0(3)IM3(2a)',
'7.0(3)IM3(2b)',
'7.0(3)IM3(3)',
'7.0(3)IM7(2)',
'7.0(3)IX1(2)',
'7.0(3)IX1(2a)',
'7.0(3)N1(1)',
'7.0(4)N1(1)',
'7.0(4)N1(1a)',
'7.0(5)N1(1)',
'7.0(5)N1(1a)',
'7.0(6)N1(1)',
'7.0(6)N1(2s)',
'7.0(6)N1(3s)',
'7.0(6)N1(4s)',
'7.0(7)N1(1)',
'7.0(7)N1(1a)',
'7.0(7)N1(1b)',
'7.0(8)N1(1)',
'7.0(8)N1(1a)',
'7.1(0)N1(1)',
'7.1(0)N1(1a)',
'7.1(0)N1(1b)',
'7.1(1)N1(1)',
'7.1(1)N1(1a)',
'7.1(2)N1(1)',
'7.1(2)N1(1a)',
'7.1(3)N1(1)',
'7.1(3)N1(2)',
'7.1(3)N1(2a)',
'7.1(3)N1(3)',
'7.1(3)N1(4)',
'7.1(3)N1(5)',
'7.1(4)N1(1)',
'7.1(4)N1(1a)',
'7.1(4)N1(1c)',
'7.1(4)N1(1d)',
'7.1(5)N1(1)',
'7.2(0)D1(1)',
'7.2(0)N1(1)',
'7.2(1)D1(1)',
'7.2(1)N1(1)',
'7.2(2)D1(1)',
'7.2(2)D1(2)',
'7.2(2)D1(3)',
'7.2(2)D1(4)',
'7.3(0)D1(1)',
'7.3(0)DX(1)',
'7.3(0)DY(1)',
'7.3(0)N1(1)',
'7.3(0)N1(1a)',
'7.3(0)N1(1b)',
'7.3(1)D1(1)',
'7.3(1)DY(1)',
'7.3(1)N1(1)',
'7.3(2)D1(1)',
'7.3(2)D1(2)',
'7.3(2)D1(3)',
'7.3(2)D1(3a)',
'7.3(2)N1(1)',
'7.3(2)N1(1b)',
'7.3(2)N1(1c)',
'7.3(3)N1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['cfs_enabled']);
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
