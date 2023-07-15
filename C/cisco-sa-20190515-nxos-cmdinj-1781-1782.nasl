#TRUSTED 139497bf8f2337206c331a80e05c6b869caa1f73a78b6300502357bade60a058180012dee903dc078bf90103d695cc4956daa1dcda479221fbcfdc585f5f843b8a7a04807f2b738df393c5af40d7b92870758d92eba59a87ea1c4aade12c11d21370e5c98d7d7cc7c56db16066defa0153a89b73f0d9d75d1a45f15d6dab211412c62e32dbe86918540929c2b63661eb2031fe4f9d09df56c05666a74430bc914ac7713d075a436ac0b3c2a07ae65c81a128a8df85929a3cdf1ce03c3dfbaed24f032115f4c1b4e300e30f0dd5cb299512a80bbc8b206bbd232a8c89c11fba812c50243f3fb401aeeff22d0f45e3a9b5f71220684906094fb70f8a4b995d6a9e3b12c19794615e63ffc47fbe44ceb5dd0f09b3be06542e52648264613a4c3d08b7a6478523709c15a8cd1b41550feca8f8270161b84ebf98a9c8ae463ce1bb81855e812469124578d7a9c8dcd3c51d8516f2a775d4c13dffd74a6e99d5d4810ece91d7a5ca0109efffde0c31f959f18bc798efb06f05fc5e329bd9451e28ba869cf4bc9ac7663ef0c2e90224e4be80cfc354e95ab590fab8dad5f43ee27067d4a3b37c89a9fd27045f543faeb42034fa263b85c47d36cc55fe3bcc6cda2d57b7bd0e1cbafaf3fdff4c192740f301601c533f1d2128a7e8e7ddd0b6728b78e57a5e55b74f112188575289b40a7a387dcf127c5cb7010f69025cd751a76c017cc5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129946);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1781", "CVE-2019-1782");
  script_bugtraq_id(108407);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20027");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20389");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01445");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi91985");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92126");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92128");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92129");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96522");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96524");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96525");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96526");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Command Injection Vulnerabilities (cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by vulnerabilities 
in the CLI that could allow an authenticated, local attacker to execute arbitrary commands on the
underlying operating system of an affected device. This vulnerability is due to insufficient
validation of arguments passed to certain CLI commands. An attacker could exploit this vulnerability
by including malicious input as the argument of an affected command. A successful exploit could allow
the attacker to execute arbitrary commands on the underlying operating system with elevated privileges.
An attacker would need administrator credentials to exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d66d198");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20027");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20389");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01445");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01448");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi91985");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92126");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92128");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92129");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96522");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96524");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96525");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96526");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs 
CSCvh20027, CSCvh20389, CSCvi01445, CSCvi01448, CSCvi91985, CSCvi92126, CSCvi92128,
CSCvi92129, CSCvi96522, CSCvi96524, CSCvi96525, CSCvi96526");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1781");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

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
if('MDS' >< product_info.device && product_info.model =~ "^(90|70|77)[0-9][0-9]")
  cbi = 'CSCvi01448, CSCvh20389';
else if ('UCS' >< product_info.device && product_info.model =~ "^(62|63)[0-9][0-9]")
  cbi = 'CSCvi96526, CSCvi92129';
else if('Nexus' >< product_info.device)
{
  if(product_info.model =~ "^(30|35|90)[0-9][0-9]")
    cbi = 'CSCvi01445, CSCvh20027, CSCvi96524, CSCvi92126';
  else if(product_info.model =~ "^(36|95)[0-9][0-9]")
    cbi = 'CSCvi96522, CSCvi91985';
  else if(product_info.model =~ "^(55|56|60)[0-9][0-9]")
    cbi = 'CSCvi96525, CSCvi92128';
  else if(product_info.model =~ "^(70|77)[0-9][0-9]")
    cbi = 'CSCvi01448, CSCvh20389';
}
else audit(AUDIT_HOST_NOT, 'affected');

vuln_list = [
  '3.2(3a)A',
  '4.0(0.336)',
  '6.0(2)',
  '6.0(3)',
  '6.0(4)',
  '6.0(2)A1',
  '6.0(2)A1(1)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(2d)',
  '6.0(2)A3',
  '6.0(2)A3(1)',
  '6.0(2)A3(2)',
  '6.0(2)A3(4)',
  '6.0(2)A4',
  '6.0(2)A4(1)',
  '6.0(2)A4(2)',
  '6.0(2)A4(3)',
  '6.0(2)A4(4)',
  '6.0(2)A4(5)',
  '6.0(2)A4(6)',
  '6.0(2)A6',
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
  '6.0(2)A7',
  '6.0(2)A7(1)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(2a)',
  '6.0(2)A8',
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
  '6.2',
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
  '7.0',
  '7.0(3)',
  '7.0(0)N1',
  '7.0(0)N1(1)',
  '7.0(1)N1',
  '7.0(1)N1(1)',
  '7.0(1)N1(3)',
  '7.0(2)I2',
  '7.0(2)I2(2c)',
  '7.0(2)N1',
  '7.0(2)N1(1)',
  '7.0(2)N1(1a)',
  '7.0(3)F1',
  '7.0(3)F1(1)',
  '7.0(3)F2',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)I1',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2',
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
  '7.0(3)I3',
  '7.0(3)I3(1)',
  '7.0(3)I4',
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
  '7.0(3)I7(5a)',
  '7.0(3)I5',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)IHD8(0.401)',
  '7.3',
  '7.3(0.2)',
  '7.3(0)D1',
  '7.3(0)D1(1)',
  '7.3(0)DX',
  '7.3(0)DX(1)',
  '7.3(0)DY',
  '7.3(0)DY(1)',
  '7.3(0)N1',
  '7.3(0)N1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(1)D1',
  '7.3(1)D1(1B)',
  '7.3(1)D1(1)',
  '7.3(1)DY',
  '7.3(1)DY(1)',
  '7.3(1)N1',
  '7.3(1)N1(0.1)',
  '7.3(1)N1(1)',
  '7.3(2)D1',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1',
  '7.3(2)N1(0.296)',
  '7.3(2)N1(1)',
  '7.3(3)N1',
  '7.3(3)N1(1)',
  '8.2',
  '8.2(1)',
  '8.2(2)',
  '7.3(3)D1'
];

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
  vuln_versions:vuln_list,
  switch_only:TRUE
);
