#TRUSTED b00479d249c43763733b78bb32ec4e3ac64a0dbfa14a7f5c50b996b7ad9b8e2dfe7ac08245869a7c3d99947a7c7dc2e48731eb1c041297b892421e3b7405336e336465f79f40a5e4b673d6aae0e411d806d52e2c4512bbc919b77aedd9055ab3d3eb0339e6e5ced56a232667f93b797220be0fad754168b7713e128b78af78918cbee04b0decd20cd536ca6a6dcc7e0ef284560277d44d2ba5fc73fd27c6ee4afe723008d25ee9b729a86cc6cc9327adac7953e4b332d9ee21a8eabf1dc0565f6f65cf36c080834b080f223afddc826b1b74a56a5691d25c90fd5a9f91076d3b8dca2282e7712205b3bed5f4152ff2adfcb9dfbb4623b3c4da2bf8cc8f4c24ce236080b1aaca80d321439ed85feb574df196e3973e701579dba93212a3bf2b38ee9ba5ce7bcaf9c93b161f1408acc518e5c47b7609ae1282b3c66caa373bc8b94ff9e77e2af3bc1fb74f92bf0f7893fba1f36751a98b9fa61df4b5a8af409475de7de237e5a04d18045296af0107e8ea3fac4e9af4a782b461e703c91e18540c3c9d0f424cefd1e4a09901e1f79dcdf25b9ad5e1e852570b6bdb3569c30b0ff71b2d11303d60e526fb7a8cf25bcd475b5294e1c04da3cc08e1f31d597fd18a71e7f2ceaa8d50e34df6a82acf23d91c6b459fbb6429b4904e95a1ea4396ce645e74a8ba91917362be784e0cab2c934b3e8206ce0d1bcfbdeeaaaaf4165f29e7b1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140202);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_cve_id("CVE-2020-3454");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve15011");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg11715");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg11732");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg11752");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh85161");
  script_xref(name:"CISCO-SA", value:"cisco-sa-callhome-cmdinj-zkxzSCY");
  script_xref(name:"IAVA", value:"2020-A-0394");

  script_name(english:"Cisco NX-OS Software Call Home Command Injection (cisco-sa-callhome-cmdinj-zkxzSCY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability due to
insufficient input validation of specific Call Home configuration parameters when configured for transport method
HTTP. An authenticated, remote attacker could modify parameters within the Call Home configuration in order to execute
arbitrary commands with root privileges on the underlying OS. Please see the included Cisco BIDs and Cisco Security
Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-callhome-cmdinj-zkxzSCY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?651817a0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve15011");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg11715");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg11732");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg11752");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh85161");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCve15011, CSCvg11715, CSCvg11732, CSCvg11752,
CSCvh85161");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/03");

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

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if (('MDS' >!< product_info.device || product_info.model !~ "^90[0-9][0-9]") &&
  ('Nexus' >!< product_info.device || product_info.model !~ "^([39][0-9]{3})|(55|56|60|70)[0-9]{2}"))
audit(AUDIT_HOST_NOT, 'affected');

if (!(empty_or_null(get_kb_list('Host/aci/*'))))
  audit(AUDIT_HOST_NOT, 'an affected model due to ACI mode');

cbi = NULL;
version_list = NULL;

if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9]{2}")
{
  cbi = 'CSCvh85161';
  version_list = make_list(
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
    '5.2(2)',
    '5.2(2a)',
    '5.2(2d)',
    '5.2(2s)',
    '5.2(6)',
    '5.2(6a)',
    '5.2(6b)',
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
    '6.2(1)',
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
    '6.2(17a)',
    '6.2(19)',
    '6.2(21)',
    '6.2(23)',
    '6.2(3)',
    '6.2(5)',
    '6.2(5a)',
    '6.2(5b)',
    '6.2(7)',
    '6.2(9)',
    '6.2(9a)',
    '6.2(9b)',
    '6.2(9c)',
    '7.3(0)D1(1)',
    '7.3(0)DY(1)',
    '7.3(1)D1(1)',
    '7.3(1)DY(1)',
    '8.1(1)',
    '8.1(1a)',
    '8.1(1b)',
    '8.2(1)',
    '8.2(2)'
  );
}
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCvg11715,CSCvg11752';
    version_list = make_list(
      '5.0(3)A1(1)',
      '5.0(3)A1(2)',
      '5.0(3)A1(2a)',
      '5.0(3)U1(1)',
      '5.0(3)U1(1a)',
      '5.0(3)U1(1b)',
      '5.0(3)U1(1c)',
      '5.0(3)U1(1d)',
      '5.0(3)U1(2)',
      '5.0(3)U1(2a)',
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
      '6.0(2)U6(1)',
      '6.0(2)U6(10)',
      '6.0(2)U6(10a)',
      '6.0(2)U6(1a)',
      '6.0(2)U6(2)',
      '6.0(2)U6(2a)',
      '6.0(2)U6(3)',
      '6.0(2)U6(3a)',
      '6.0(2)U6(4)',
      '6.0(2)U6(4a)',
      '6.0(2)U6(5)',
      '6.0(2)U6(5a)',
      '6.0(2)U6(5b)',
      '6.0(2)U6(5c)',
      '6.0(2)U6(6)',
      '6.0(2)U6(7)',
      '6.0(2)U6(8)',
      '6.0(2)U6(9)',
      '6.1(2)I2(2a)',
      '6.1(2)I2(2b)',
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
      '7.0(3)F3(1)',
      '7.0(3)F3(2)',
      '7.0(3)I1(1)',
      '7.0(3)I1(1a)',
      '7.0(3)I1(1b)',
      '7.0(3)I1(1z)',
      '7.0(3)I1(2)',
      '7.0(3)I1(3)',
      '7.0(3)I1(3a)',
      '7.0(3)I1(3b)',
      '7.0(3)I2(1)',
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
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
      '7.0(3)I7(1)',
      '7.0(3)IC4(4)',
      '7.0(3)IM7(2)',
      '7.0(3)IX1(2)',
      '7.0(3)IX1(2a)'
    );
  }
  else if (product_info.model =~ "^5[0-9]{3}")
  {
    cbi = 'CSCve15011';
    version_list = make_list(
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
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
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
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1a)',
      '7.3(0)N1(1b)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)'
    );
  }
    else if (product_info.model =~ "^6[0-9]{3}")
  {
    cbi = 'CSCve15011';
    version_list = make_list(
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
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
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
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1a)',
      '7.3(0)N1(1b)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)'
    );
  }
  else if (product_info.model =~ "^7[0-9]{3}")
  {
    cbi = 'CSCvg11732';
    version_list = make_list(
      '5.2(1)',
      '5.2(3)',
      '5.2(3a)',
      '5.2(4)',
      '5.2(5)',
      '5.2(7)',
      '5.2(9)',
      '5.2(9a)',
      '6.2(10)',
      '6.2(12)',
      '6.2(14)',
      '6.2(14a)',
      '6.2(14b)',
      '6.2(16)',
      '6.2(18)',
      '6.2(2)',
      '6.2(20)',
      '6.2(20a)',
      '6.2(2a)',
      '6.2(6)',
      '6.2(6a)',
      '6.2(6b)',
      '6.2(8)',
      '6.2(8a)',
      '6.2(8b)',
      '7.2(0)D1(1)',
      '7.2(1)D1(1)',
      '7.2(2)D1(1)',
      '7.2(2)D1(2)',
      '7.2(2)D1(3)',
      '7.2(2)D1(4)',
      '7.3(0)D1(1)',
      '7.3(0)DX(1)',
      '7.3(1)D1(1)',
      '7.3(2)D1(1)',
      '7.3(2)D1(1d)',
      '7.3(2)D1(2)',
      '7.3(2)D1(3)',
      '7.3(2)D1(3a)',
      '8.0(1)',
      '8.1(1)',
      '8.1(2)',
      '8.1(2a)',
      '8.2(1)',
      '8.2(2)'
    );
  }
  else if (product_info.model =~ "^9[0-9]{3}")
  {
    cbi = 'CSCvg11715,CSCvg11752';
    version_list = make_list(
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
      '6.1(2)I3(5a)',
      '6.1(2)I3(5b)',
      '7.0(3)F1(1)',
      '7.0(3)F2(1)',
      '7.0(3)F2(2)',
      '7.0(3)F3(1)',
      '7.0(3)I1(1)',
      '7.0(3)I1(1a)',
      '7.0(3)I1(1b)',
      '7.0(3)I1(1z)',
      '7.0(3)I1(2)',
      '7.0(3)I1(3)',
      '7.0(3)I1(3a)',
      '7.0(3)I1(3b)',
      '7.0(3)I2(1)',
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
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
      '7.0(3)I7(1)',
      '7.0(3)IC4(4)',
      '7.0(3)IM3(1)',
      '7.0(3)IM3(2)',
      '7.0(3)IM3(2a)',
      '7.0(3)IM3(2b)',
      '7.0(3)IM3(3)'
    );
  }
  else audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['callhome_destination-profile_http'];

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

