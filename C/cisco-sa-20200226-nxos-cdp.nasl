#TRUSTED 982af7f0805207e854637926340064674164bd6e25a9756883b0f577abfc78f5a926884431599fa4a87cbe5c503069493ea439ab0aaa63a2c0b82198575ea58d757a60bd02526feb7945cba999c06dfbe4612cc366840798e955d905015ae9fe3db788f7d8dc299fe1002b513ef1bce6ba38e7c42a19dcabd71decc571806c75824d27a7781d539773f7c522a63dbd314ed640d50650a1569f0d898f74da070247acf3bd264939a53a8a56e8ec72b6a56cd6564f03add75d1c9cf1fb5eb110db9b124fefd4578eca888d5acdae7c1809f13e30ecf66e70ce31fea75cf9b0ae4ca5faa9843311438e761013adf1af12a670e8aa57d715e467590224a0a482815b8c0ddbe31099a7842c487eef9fbeac309718a806c4af8ba7c7b4ecb87ec22cd3bca18834a95725b2eec0ad999a37d27391af8893882d6bbc0f7b391da8ca2272a1a1458908854543cd962a9a8f8102302bebf583070c66eaab17f1addcba64ef8f6749b21726e85c8cd242754e3619cc40d35e4ec86c944e487e861dd147f272df45faaff069ceb88ce2f179a751be6e165c151bce4dc51f7b5edb89360f2a7aacdeb8c17d1e6a8a2e3902d0a19166f8f6ed0d486bd73acb6165fb3b762d255c63ae203b8d6863ed47604a512c438063254a4ef3a0b96e244cfb8e8a1f4f4eb82bacc5680977da7e4f4128fd553fb542a67ca9b96858737e0f6f526e89f5e19f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134235);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/18");

  script_cve_id("CVE-2020-3172");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux07556");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux58226");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr31410");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr37146");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr37148");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr37150");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-nxos-cdp");
  script_xref(name:"IAVA", value:"2020-A-0086");

  script_name(english:"Cisco NX-OS Software Cisco Discovery Protocol Arbitrary Code Execution and DoS (cisco-sa-20200226-fxos-nxos-cdp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Cisco Discovery
Protocol feature due to insufficient validation of Cisco Discovery Protocol packet headers. An unauthenticated, adjacent
attacker can exploit this, by sending a crafted Cisco Discovery Protocol packet to a Layer-2 adjacent affected device,
in order to execute arbitrary code as root or cause a denial of service DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fxos-nxos-cdp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be9c7431");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be9c7431/");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux07556");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux58226");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr31410");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr37146");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr37148");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr37150");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCux07556, CSCux58226, CSCvr31410, CSCvr37146,
CSCvr37148, and CSCvr37150.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3172");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

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
include('lists.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
if ('Nexus' >< product_info.device)
{
  if (product_info.model =~  "^10[0-9]{2}")
  {
    cbi = 'CSCvr37146';
    version_list = make_list(
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
      '5.2(1)SK3(1.1)',
      '5.2(1)SK3(2.1)',
      '5.2(1)SK3(2.2)',
      '5.2(1)SK3(2.2b)',
      '5.2(1)SK3(2.1a)',
      '5.2(1)SV5(1.1)',
      '5.2(1)SV5(1.2)');
  }
  else if (product_info.model =~ "^9[0-9]{3}")
  {
    cbi = 'CSCvr31410, CSCux58226';
    version_list = make_list(
      '6.1(2)',
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
      '7.0(3)F1(1)',
      '7.0(3)F2(1)',
      '7.0(3)F2(2)',
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
      '11.0(1b)',
      '11.0(1c)',
      '11.0(1d)',
      '11.0(1e)',
      '11.0(2j)',
      '11.0(2m)',
      '11.0(3f)',
      '11.0(3i)',
      '11.0(3k)',
      '11.0(3n)',
      '11.0(3o)',
      '11.0(4h)',
      '11.0(4o)',
      '11.0(4q)',
      '11.0(4g)',
      '11.1(1j)',
      '11.1(1o)',
      '11.1(1r)',
      '11.1(1s)',
      '11.1(2h)',
      '11.1(2i)',
      '11.1(3f)',
      '11.1(4e)',
      '11.1(4f)',
      '11.1(4g)',
      '11.1(4i)',
      '11.1(4l)',
      '11.1(4m)',
      '11.2(1i)',
      '11.2(2g)',
      '11.2(3c)',
      '11.2(2h)',
      '11.2(2i)',
      '11.2(3e)',
      '11.2(3h)',
      '11.2(3m)',
      '11.2(1k)',
      '11.2(1m)',
      '11.2(2j)',
      '12.0(1m)',
      '12.0(2g)',
      '12.0(1n)',
      '12.0(1o)',
      '12.0(1p)',
      '12.0(1q)',
      '12.0(2h)',
      '12.0(2l)',
      '12.0(2m)',
      '12.0(2n)',
      '12.0(2o)',
      '12.0(2f)',
      '12.0(1r)',
      '12.1(1h)',
      '12.1(2e)',
      '12.1(3g)',
      '12.1(4a)',
      '12.1(1i)',
      '12.1(2g)',
      '12.1(2k)',
      '12.1(3h)',
      '12.1(3j)',
      '12.2(1n)',
      '12.2(2e)',
      '12.2(3j)',
      '12.2(4f)',
      '12.2(4p)',
      '12.2(3p)',
      '12.2(3r)',
      '12.2(3s)',
      '12.2(3t)',
      '12.2(2f)',
      '12.2(2i)',
      '12.2(2j)',
      '12.2(2k)',
      '12.2(2q)',
      '12.2(1o)',
      '12.2(4q)',
      '12.2(4r)',
      '12.2(1k)',
      '12.3(1e)',
      '12.3(1f)',
      '12.3(1i)',
      '12.3(1l)',
      '12.3(1o)',
      '12.3(1p)',
      '13.0(1k)',
      '13.0(2h)',
      '13.0(2k)',
      '13.0(2n)',
      '13.1(1i)',
      '13.1(2m)',
      '13.1(2o)',
      '13.1(2p)',
      '13.1(2q)',
      '13.1(2s)',
      '13.1(2t)',
      '13.1(2u)',
      '13.1(2v)',
      '13.2(1l)',
      '13.2(1m)',
      '13.2(2l)',
      '13.2(2o)',
      '13.2(3i)',
      '13.2(3n)',
      '13.2(3o)',
      '13.2(3r)',
      '13.2(4d)',
      '13.2(4e)',
      '13.2(3s)',
      '13.2(5d)',
      '13.2(5e)',
      '13.2(5f)',
      '13.2(6i)',
      '13.2(41d)',
      '13.2(7f)',
      '13.2(7k)',
      '11.3(1g)',
      '11.3(2f)',
      '11.3(1h)',
      '11.3(1i)',
      '11.3(2h)',
      '11.3(2i)',
      '11.3(2k)',
      '11.3(1j)',
      '11.3(2j)',
      '14.0(1h)',
      '14.0(2c)',
      '14.0(3d)',
      '14.0(3c)',
      '14.1(1i)',
      '14.1(1j)',
      '14.1(1k)',
      '14.1(1l)',
      '14.1(2g)',
      '14.1(2m)',
      '14.1(2o)',
      '14.1(2s)',
      '14.1(2u)',
      '14.1(2w)',
      '14.1(2x)',
      '14.2(1i)');
  }
  else if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCux58226';
    version_list = make_list(
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
      '6.1(2)I2(2a)',
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
      '7.0(3)IX1(2)',
      '7.0(3)IX1(2a)');
  }
  else if (product_info.model =~ "^(55|56)[0-9]{2}")
  {
    cbi = 'CSCvr37148';
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
      '5.2(1)N1(8a)',
      '5.2(1)N1(8)',
      '5.2(1)N1(8b)',
      '5.2(1)N1(9)',
      '5.2(1)N1(9a)',
      '5.2(1)N1(9b)',
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
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
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
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1b)',
      '7.3(0)N1(1a)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)',
      '7.3(3)N1(1)',
      '7.3(4)N1(1)',
      '7.3(4)N1(1a)',
      '7.3(5)N1(1)',
      '7.3(6)N1(1)',
      '7.3(6)N1(1a)');
  }
  else if (product_info.model =~ "^60[0-9]{2}")
  {
    cbi = 'CSCvr37148';
    version_list = make_list(
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
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
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
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1b)',
      '7.3(0)N1(1a)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)',
      '7.3(3)N1(1)',
      '7.3(4)N1(1)',
      '7.3(4)N1(1a)',
      '7.3(5)N1(1)',
      '7.3(6)N1(1)',
      '7.3(6)N1(1a)');
  }
  else if (product_info.model =~ "^70[0-9]{2}")
  {
    cbi = 'CSCux07556';
    version_list = make_list(
      '5.2(1)',
      '5.2(3a)',
      '5.2(4)',
      '5.2(5)',
      '5.2(7)',
      '5.2(9)',
      '5.2(3)',
      '5.2(9a)',
      '6.1(1)',
      '6.1(2)',
      '6.1(3)',
      '6.1(4)',
      '6.1(4a)',
      '6.1(5)',
      '6.1(5a)',
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
      '6.2(20a)',
      '6.2(22)',
      '7.2(0)D1(1)',
      '7.2(1)D1(1)',
      '7.2(2)D1(2)',
      '7.2(2)D1(1)',
      '7.2(2)D1(3)',
      '7.2(2)D1(4)');
  }
}
else if ('MDS' >< product_info.device && (product_info.model =~ "^90[0-9]{2}"))
{
  cbi = 'CSCux07556';
  version_list = make_list(
    '5.2(1)',
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
    '6.2(25)',
    '6.2(17a)',
    '6.2(27)',
    '6.2(29)');
}
else if ('UCS' >< product_info.device && (product_info.model =~ "^6(2|3)[0-9]{2}"))
{
  cbi = 'CSCvr37150';
  version_list = make_list(
    '11.0(1b)',
    '11.0(1c)',
    '11.0(1d)',
    '11.0(1e)',
    '11.0(2j)',
    '11.0(2m)',
    '11.0(3f)',
    '11.0(3i)',
    '11.0(3k)',
    '11.0(3n)',
    '11.0(3o)',
    '11.0(4g)',
    '11.0(4h)',
    '11.0(4o)',
    '11.0(4q)',
    '11.1(1j)',
    '11.1(1o)',
    '11.1(1r)',
    '11.1(2h)',
    '11.1(2i)',
    '11.1(3f)',
    '11.1(4e)',
    '11.1(4f)',
    '11.1(4g)',
    '11.1(4i)',
    '11.1(4l)',
    '11.1(4m)',
    '11.2(1i)',
    '11.2(1k)',
    '11.2(1m)',
    '11.2(2g)',
    '11.2(2h)',
    '11.2(2i)',
    '11.2(2j)',
    '11.2(3c)',
    '11.2(3e)',
    '11.2(3h)',
    '11.2(3m)',
    '11.3(1g)',
    '11.3(1h)',
    '11.3(1i)',
    '11.3(1j)',
    '11.3(2f)',
    '11.3(2h)',
    '11.3(2i)',
    '11.3(2j)',
    '11.3(2k)',
    '12.0(1m)',
    '12.0(1n)',
    '12.0(1o)',
    '12.0(1p)',
    '12.0(1q)',
    '12.0(1r)',
    '12.0(2f)',
    '12.0(2g)',
    '12.0(2h)',
    '12.0(2l)',
    '12.0(2m)',
    '12.0(2n)',
    '12.0(2o)',
    '12.1(1h)',
    '12.1(1i)',
    '12.1(2e)',
    '12.1(2g)',
    '12.1(2k)',
    '12.1(3g)',
    '12.1(3h)',
    '12.1(3j)',
    '12.1(4a)',
    '12.2(1k)',
    '12.2(1n)',
    '12.2(1o)',
    '12.2(2e)',
    '12.2(2f)',
    '12.2(2i)',
    '12.2(2j)',
    '12.2(2k)',
    '12.2(2q)',
    '12.2(3j)',
    '12.2(3p)',
    '12.2(3r)',
    '12.2(3t)',
    '12.2(4f)',
    '12.2(4p)',
    '12.2(4q)',
    '12.2(4r)',
    '12.3(1e)',
    '12.3(1f)',
    '12.3(1i)',
    '12.3(1l)',
    '12.3(1o)',
    '12.3(1p)',
    '13.0(1k)',
    '13.0(2h)',
    '13.0(2k)',
    '13.0(2n)',
    '13.1(1i)',
    '13.1(2m)',
    '13.1(2o)',
    '13.1(2p)',
    '13.1(2q)',
    '13.1(2t)',
    '13.1(2u)',
    '13.1(2v)',
    '13.2(1l)',
    '13.2(1m)',
    '13.2(2l)',
    '13.2(2o)',
    '13.2(3i)',
    '13.2(3n)',
    '13.2(3o)',
    '13.2(3r)',
    '13.2(41d)',
    '13.2(4d)',
    '13.2(4e)',
    '13.2(5d)',
    '13.2(5e)',
    '13.2(5f)',
    '13.2(6i)',
    '13.2(7f)',
    '13.2(7k)',
    '14.0(1h)',
    '14.0(2c)',
    '14.0(3c)',
    '14.0(3d)',
    '14.1(1i)',
    '14.1(1j)',
    '14.1(1k)',
    '14.1(1l)',
    '14.1(2g)',
    '14.1(2m)',
    '14.1(2o)',
    '14.1(2u)',
    '14.1(2w)',
    '14.1(2x)',
    '14.2(1i)',
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
    '5.2(1)SK3(1.1)',
    '5.2(1)SK3(2.1)',
    '5.2(1)SK3(2.1a)',
    '5.2(1)SK3(2.2)',
    '5.2(1)SK3(2.2b)',
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
    '5.2(1)SV3(1.1)',
    '5.2(1)SV3(1.10)',
    '5.2(1)SV3(1.15)',
    '5.2(1)SV3(1.2)',
    '5.2(1)SV3(1.3)',
    '5.2(1)SV3(1.4)',
    '5.2(1)SV3(1.4b)',
    '5.2(1)SV3(1.5a)',
    '5.2(1)SV3(1.5b)',
    '5.2(1)SV3(1.6)',
    '5.2(1)SV3(2.1)',
    '5.2(1)SV3(2.5)',
    '5.2(1)SV3(2.8)',
    '5.2(1)SV3(3.1)',
    '5.2(1)SV3(3.15)',
    '5.2(1)SV3(4.1)',
    '5.2(1)SV3(4.1a)',
    '5.2(1)SV5(1.1)',
    '5.2(1)SV5(1.2)',
    '5.2(2)',
    '5.2(2a)',
    '5.2(2d)',
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
    '6.0(2)A8(10)',
    '6.0(2)A8(10a)',
    '6.0(2)A8(11)',
    '6.0(2)A8(11a)',
    '6.0(2)A8(11b)',
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
    '6.0(2)U6(1)',
    '6.0(2)U6(10)',
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
    '6.1(2)I3(5a)',
    '6.1(2)I3(5b)',
    '6.1(3)',
    '6.1(4)',
    '6.1(4a)',
    '6.1(5)',
    '6.1(5a)',
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
    '6.2(22)',
    '6.2(23)',
    '6.2(25)',
    '6.2(27)',
    '6.2(29)',
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
    '7.0(3)I2(2v)',
    '7.0(3)I2(2w)',
    '7.0(3)I2(2x)',
    '7.0(3)I2(2y)',
    '7.0(3)I2(3)',
    '7.0(3)I2(4)',
    '7.0(3)I2(5)',
    '7.0(3)IX1(2)',
    '7.0(3)IX1(2a)',
    '7.0(3)N1(1)',
    '7.0(4)N1(1)',
    '7.0(4)N1(1a)',
    '7.0(5)N1(1)',
    '7.0(5)N1(1a)',
    '7.0(6)N1(1)',
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
    '7.1(5)N1(1b)',
    '7.2(0)D1(1)',
    '7.2(0)N1(1)',
    '7.2(1)D1(1)',
    '7.2(1)N1(1)',
    '7.2(2)D1(1)',
    '7.2(2)D1(2)',
    '7.2(2)D1(3)',
    '7.2(2)D1(4)',
    '7.3(0)N1(1)',
    '7.3(0)N1(1a)',
    '7.3(0)N1(1b)',
    '7.3(1)N1(1)',
    '7.3(2)N1(1)',
    '7.3(2)N1(1b)',
    '7.3(2)N1(1c)',
    '7.3(3)N1(1)',
    '7.3(4)N1(1)',
    '7.3(4)N1(1a)',
    '7.3(5)N1(1)',
    '7.3(6)N1(1)',
    '7.3(6)N1(1a)');
}

if (cbi == '')
  audit(AUDIT_HOST_NOT, 'an affected model');

# Versions that were not associated with any particular model but still appeared in the CVRF
common_version_list=make_list(
  '12.2(2g)',
  '13.0(1i)',
  '13.0(2m)'
);

if (!empty_or_null(version_list))
  version_list = collib::union(version_list, common_version_list);
else
  version_list = common_version_list;

workarounds = make_list(CISCO_WORKAROUNDS['nxos_cdp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi,
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workaround_params:workaround_params,
  switch_only:TRUE,
  workarounds:workarounds
);
