#TRUSTED 59abf66b20bf6bd9e27356c7b4346b74efbc9effb7ec10e4fd3166cbdc86c93ebedecfe265c516e77bf30f6c2dce8ced0d772cb05dbbe1f80954396cf3682306ff81db82732f7360ce8606365d4aceb6b7bc13142b2952a1410069659831b3f900ad3378296fa8bf439405aa4f850d6b288011513228ceceebaa83500279f87d889d69e6a84d49d6dffd4911365345d59115bab13970b9337022341894c4da9c288ccb4412bf18da6d18f17c29e71ecaf805eacdf8d7568f4b75f095c0522a477fbda8867131270c9b243945a852e8605c3a5be88ad0c3796f067d1f0991e91ab60cdb74d03e6d15f80064f4917e40547b49dd6b4855171680da7ba2e6d6438fc777f099b6807ceca94e257af9e29b3b06722887af40adb5c4553776623924c1df4c39aafe378748c133476ef91b72ddbf6eb65f625e808139ad28322c53947c0e1390b018f7b2a56a8c3ef4313dcdb246edf5a255bc85f6ddc16cf481c2d491e35609d38a1937b0f08495a460e9e8c094829b3225cc5f33f32833877b8ef712e84b647b4b4ae4544be00e938453e45db77445cfe4a21586649bae55d2aedd8bbd6924b64d237706e07a5b3d8b2b9972dafcb0a05d2c97b4a76b854903312f16ea775a9a20fe43d06d79e6fe444336c2720d984496cbb94749b0253c10197cb74035b4a0e82bc56c23f4380678e454f115d61673dc1cf233a5eff52afcdeb3e5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132055);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/16");

  script_cve_id("CVE-2019-1613");
  script_bugtraq_id(107392);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj63807");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj65654");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk50903");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk50906");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-cmdinj-1613");

  script_name(english:"Cisco NX-OS Software CLI Command Injection Vulnerability (CVE-2019-1613)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the CLI of Cisco NX-OS
Software that could allow an authenticated, local attacker to execute arbitrary commands on the underlying operating
system of an affected device.The vulnerability is due to insufficient validation of arguments passed to certain CLI
commands. An attacker could exploit this vulnerability by including malicious input as the argument of an affected
command. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system
with elevated privileges. An attacker would need valid administrator credentials to exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-cmdinj-1613
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f5871d9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj63807");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj65654");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk50903");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk50906");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj63807, CSCvj65654, CSCvk50903, and CSCvk50906.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = NULL;
if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9][0-9]")
  cbi = 'CSCvj63807';
if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvj63807';
  if (product_info.model =~ '^[39]0[0-9][0-9]')
    cbi = 'CSCvj65654';
  if (product_info.model =~ '^35[0-9][0-9]')
    cbi = 'CSCvk50906';
  if (product_info.model =~ '^(36|95)[0-9][0-9]')
    cbi = 'CSCvk50903';
}
if (empty_or_null(cbi))
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '8.2(2)',
  '8.2(1)',
  '8.1(2a)',
  '8.1(2)',
  '8.1(1b)',
  '8.1(1a)',
  '8.1(1)',
  '8.0(1)',
  '7.3(3)D1(1)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(1)D1(1)',
  '7.2(0)D1(1)',
  '7.0(3)IX1(2a)',
  '7.0(3)IX1(2)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(5)',
  '7.0(3)I7(4)',
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)',
  '7.0(3)I4(8z)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8)',
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
  '7.0(3)F3(3c)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(2)I2(2c)',
  '6.2(9c)',
  '6.2(9b)',
  '6.2(9a)',
  '6.2(9)',
  '6.2(8b)',
  '6.2(8a)',
  '6.2(8)',
  '6.2(7)',
  '6.2(6b)',
  '6.2(6a)',
  '6.2(6)',
  '6.2(5b)',
  '6.2(5a)',
  '6.2(5)',
  '6.2(3)',
  '6.2(2a)',
  '6.2(25)',
  '6.2(23)',
  '6.2(21)',
  '6.2(20a)',
  '6.2(20)',
  '6.2(2)',
  '6.2(19)',
  '6.2(18)',
  '6.2(17)',
  '6.2(16)',
  '6.2(15)',
  '6.2(14)',
  '6.2(13b)',
  '6.2(13a)',
  '6.2(13)',
  '6.2(12)',
  '6.2(11e)',
  '6.2(11d)',
  '6.2(11c)',
  '6.2(11b)',
  '6.2(11)',
  '6.2(10)',
  '6.2(1)',
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
  '6.0(2)A8(9)',
  '6.0(2)A8(8)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7)',
  '6.0(2)A8(6)',
  '6.0(2)A8(5)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(4)',
  '6.0(2)A8(3)',
  '6.0(2)A8(2)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
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

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
