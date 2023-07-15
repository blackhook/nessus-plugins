#TRUSTED 0342641e32e38df7b49f1c5badb9650565bc4191f4d5a97c39987db0cb15b3236b20aee09c641a9b29917acb8bd40f5c0dfde156fffbb6c4cdb151d954452977f368641efad725ef1d272b7cef277eceb57ba315e8b0f01384d3c9c2f5b36d7d71ef6622f29887f131672a0207910ee178954d1c4aacbaf51771a899a8e96c8b9a54a3f537474dbeb7036a1952ab380fe5f2d77eef2e1db6e4476e4c4e3242e74c5c59ca150769dd273adbc1e753082945aa23ab9e158b9a6ba1999a1ae69416db40965bf994f16c915d8fa521607c9ad7309857a8723f589cfcd39a0485fab7d418b77777a78f3b4fafb7638cd18cfb54f389f1ab269b9e1359b8716ba9290d78ad981ff1b0bd3169acfea665bb3514fd349c5153f86edb6187274ab2d016bcbdbe2df635356213256ba36baa176174d3c9aa126e7d9c3b397168a585f332f7a9ccc5dc2ac1aeceaa1abf444ceb77b145c9515ee9b9c93e992cf8439cd55e9411f14be83509b23806fbd390287ce3ca5b883ee2a4a2e230e1711a6f0eb0b1e3ec6ce182635d79c0f201c7b1b359751fda2d33b0cc55482b8754cf5f641cadb0fc52224ca607be263cc02aa16d91cbb227ac35aa3bab8ba48b9a1800724a833c37e0feaed266d760c3ff4c40dfec5d61b6dcb9889196d4444e8dfb9a2b5d2406c884c4e1e5d57ae4cd2c6034de34760ddd50c58a36f9b8649e4e50a560a0d4e9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132318);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2019-1605");
  script_bugtraq_id(107313);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh77526");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99224");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99225");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99227");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99228");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nx-os-api-ex");

  script_name(english:"Cisco NX-OS Software NX-API Arbitrary Code Execution Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the NX-API feature of
Cisco NX-OS Software that could allow an authenticated, local attacker to execute arbitrary code as root. The
vulnerability is due to incorrect input validation in the NX-API feature. An attacker could exploit this vulnerability
by sending a crafted HTTP or HTTPS request to an internal service on an affected device that has the NX-API feature
enabled. A successful exploit could allow the attacker to cause a buffer overflow and execute arbitrary code as root.
Note: The NX-API feature is disabled by default.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-api-ex
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4326b1dc");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh77526");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99224");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99225");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99227");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99228");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh77526, CSCvi99224, CSCvi99225, CSCvi99227, and
CSCvi99228");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1605");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
  cbi = 'CSCvi99225';
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^[39]0[0-9][0-9]')
    cbi = 'CSCvh77526';
  else if (product_info.model =~ '^(36|95)[0-9][0-9]')
    cbi = 'CSCvi99224';
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvi99225';
  else if (product_info.model =~ '^35[0-9][0-9]')
    cbi = 'CSCvi99227';
  else if (product_info.model =~ '^(20|5[56]|60)[0-9][0-9]')
    cbi = 'CSCvi99228';
  else
    audit(AUDIT_HOST_NOT, 'affected');
}
else
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1)',
  '7.3(1)N1(1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1)',
  '7.3(0)N1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(1)D1(1)',
  '7.2(0)D1(1)',
  '7.0(3)IX1(2a)',
  '7.0(3)IX1(2)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)',
  '7.0(3)I4(7)',
  '7.0(3)I4(6)',
  '7.0(3)I4(5)',
  '7.0(3)I4(4)',
  '7.0(3)I4(3)',
  '7.0(3)I4(2)',
  '7.0(3)I4(1)',
  '7.0(3)I3(1)',
  '7.0(3)I2(5)',
  '7.0(3)I2(4)',
  '7.0(3)I2(3)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(1)',
  '7.0(3)I1(3b)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3)',
  '7.0(3)I1(2)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(2)I2(2c)',
  '6.1(2)I3(5b)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(3)',
  '6.1(2)I3(2)',
  '6.1(2)I3(1)',
  '6.1(2)I2(3)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(2)',
  '6.1(2)I2(1)',
  '6.1(2)I1(3)',
  '6.1(2)I1(1)',
  '6.1(2)',
  '6.0(2)U6(9)',
  '6.0(2)U6(8)',
  '6.0(2)U6(7)',
  '6.0(2)U6(6)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(4)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(3)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(2)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(10)',
  '6.0(2)U6(1)',
  '6.0(2)U5(4)',
  '6.0(2)U5(3)',
  '6.0(2)U5(2)',
  '6.0(2)U5(1)',
  '6.0(2)U4(4)',
  '6.0(2)U4(3)',
  '6.0(2)U4(2)',
  '6.0(2)U4(1)',
  '6.0(2)U3(9)',
  '6.0(2)U3(8)',
  '6.0(2)U3(7)',
  '6.0(2)U3(6)',
  '6.0(2)U3(5)',
  '6.0(2)U3(4)',
  '6.0(2)U3(3)',
  '6.0(2)U3(2)',
  '6.0(2)U3(1)',
  '6.0(2)U2(6)',
  '6.0(2)U2(5)',
  '6.0(2)U2(4)',
  '6.0(2)U2(3)',
  '6.0(2)U2(2)',
  '6.0(2)U2(1)',
  '6.0(2)U1(4)',
  '6.0(2)U1(3)',
  '6.0(2)U1(2)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(1)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7)',
  '6.0(2)A8(6)',
  '6.0(2)A8(5)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(4)',
  '6.0(2)A8(3)',
  '6.0(2)A8(2)',
  '6.0(2)A8(1)',
  '6.0(2)A7(2a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(1)',
  '6.0(2)A6(8)',
  '6.0(2)A6(7)',
  '6.0(2)A6(6)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(4)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(3)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(2)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(1)',
  '6.0(2)A4(6)',
  '6.0(2)A4(5)',
  '6.0(2)A4(4)',
  '6.0(2)A4(3)',
  '6.0(2)A4(2)',
  '6.0(2)A4(1)',
  '6.0(2)A3(4)',
  '6.0(2)A3(2)',
  '6.0(2)A3(1)',
  '6.0(2)A1(2d)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1)',
  '5.0(3)U5(1j)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1)',
  '5.0(3)U4(1)',
  '5.0(3)U3(2b)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2)',
  '5.0(3)U3(1)',
  '5.0(3)U2(2d)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2)',
  '5.0(3)U2(1)',
  '5.0(3)U1(2a)',
  '5.0(3)U1(2)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(1c)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1)',
  '5.0(3)A1(2a)',
  '5.0(3)A1(2)',
  '5.0(3)A1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_nxapi'];


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
