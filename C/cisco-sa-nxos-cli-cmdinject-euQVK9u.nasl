#TRUSTED a202ca64cfbe268193afdac4a4c6bb3309ec24bd2ef71d922e13d150f955d81c62d5907d2aed87d1f08d0349f26ba21dae4394fa8f391732319f7020421abc8602da8bb1b8df23eea855a7523bb21d6b00f052bb0d6dc3b2fb17f57bb5a2537a6cf176b52575e3c2a658451fd9aac35f6d8d41ffb6ad37f57fca7603a13bbb4a7be840c02887f408d43a76a5af6fced2db52329935ff13530ac7612a9c4de554231650b0653daed74dbaa7d59cf6dc15c2687c33bd37b8d97528d29f05c6a7485d2e13d72a834928bccc936aff593cbf8909b9f9f8180a86fc4e14a26456b0ffdad50da221692266c548d0c2b29b5d72310baee9696ca3cba78ddfc4686ac1671abf4012ba029cd0e30718c43d3e9ed9dfafa78842736675026caffa6f3121bc8310eefaf57eefc9df9efab067c4588dc85b507a5897c2ff113674bf68ca62b223653f12016e9a83fe812aaa42f4e63051f778664fe06c1e8887de5160cb4ba0f88332ad47f959ec873cbe33f203d209d9f46585c95a305a5779b5fd597c1da7b28b033dc491e61e5484e315a4de1bc91483ec41075f7ce3776892ae72a0fbac295a0242b193afa98bfbba7ad3e798ff7a44faad117482e45d484b1ed84627c53369cfa5dad5bea3b4b85c9f0abffc6335502798b9a753b4492134f3e26e465276e66affea0de988ca0444fdcafca6f5658a840cc93e552b3dcfdc742096bc0d
#TRUST-RSA-SHA256 419ec8c65ed658182ed8eae876f3c127ba4e67e3324a90abcf8f225f34b42d7445aa92e3810e63a5c20adf1de298abdadc4a65d20733548993a73fde884993f2cd6e4206a2979ef907c9e3e38a436965aff9ed94eefa3e8d3cd69eb621c8d854f6b06c54210acf16a6fbc4d30c84f03bc8174c1949d454558401f8b03d8dfe3039209a36f8881a98ca9b6c3b0101fe659765635d7e6f76f7a9995d9773664d781667aeca2eaaa5ce033b5a2dd018a5a936832c0ac289d6a4bbcc4dc2e6738651dce9cba9819516d0daf5d36baed23f704fe89121dfbbc101aea1051e5aaffa7de646a2a171b6e86c7f07810c45586428a6ad4f2c7e9b1a59fdc32af87efaf678e7cf2b3cbe760d736507c1d800b034718378c7840c466a6aafc8912601cc94a758031da6cabb99d9e484fb31fecf4c422f89f9b0355e2e618982ec64f6a3500959610c768310857186f7cbdefeb4f772d4b53505b7926a7e746e757e6902a946fc2bcc17698d2a6098ded4127ffbd2d03995fa21e7a4cb0b8f6bb550b14cd44854d66e7edccaf67fc13f364898cb23f76c9423ac9474908e40855128832ac5b9735c297c1e569570d2e4d8b55ae184f60bd3c70f7af0cf86cc6a6dccbfb37f38c6cb0cb8ec7383a0a600d26471969ec6464cabedd635b3a9d5d53c9ab24fc2eca0442f379e9db392cf9aedd2bf3c276b16d796f3f9e996a2f6b2159d6176133f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171838);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2023-20050");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd00653");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd18009");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd18011");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd18012");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd18013");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-cli-cmdinject-euQVK9u");
  script_xref(name:"IAVA", value:"2023-A-0120");

  script_name(english:"Cisco NX-OS Software CLI Comm Injection (cisco-sa-nxos-cli-cmdinject-euQVK9u)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco NX-OS Software could allow an authenticated, local attacker to execute
    arbitrary commands on the underlying operating system of an affected device. This vulnerability is due to
    insufficient validation of arguments that are passed to specific CLI commands. An attacker could exploit
    this vulnerability by including crafted input as the argument of an affected command. A successful exploit
    could allow the attacker to execute arbitrary commands on the underlying operating system with the
    privileges of the currently logged-in user. (CVE-2023-20050)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cli-cmdinject-euQVK9u
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c662ba3d");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75057
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?824d6bb6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd00653");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd18009");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd18011");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd18012");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd18013");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd00653, CSCwd18009, CSCwd18011, CSCwd18012,
CSCwd18013");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20050");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');


if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])1[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])3[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])7[0-9]{2,3}") &&
    ('MDS' >!< product_info.device || product_info.model !~ "^9[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])5[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])6[0-9]{2,3}"))
audit(AUDIT_HOST_NOT, 'affected');

# Check if installed patch fix listed in Active package list
var show_ver = get_kb_item('Host/Cisco/show_ver');
if (!empty_or_null(show_ver))
{
  foreach var patch (['n7000-s2-dk9.8.2.9.CSCwd18011', 
                      'n7700-s2-dk9.8.2.9.CSCwd18011', 
                      'nxos.CSCwd00653-n9k_ALL-1.0.0-9.3.10.lib32_n9000', 
                      'nxos64-cs.CSCwd00653-1.0.0-10.2.4.lib32_64_n9000',
                      'nxos64-msll.CSCwd00653-1.0.0-10.2.4.lib32_64_n9000'])
  {
    if (patch >< show_ver)
      audit(AUDIT_HOST_NOT, 'affected');
  }
}

var version_list = [];

if ('Nexus' >< product_info.device && product_info.model =~ "^1[0-9]{2,3}")
{
  version_list = make_list(
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
    '5.2(1)SV3(4.1b)',
    '5.2(1)SV3(4.1c)',
    '5.2(1)SK3(1.1)',
    '5.2(1)SK3(2.1)',
    '5.2(1)SK3(2.2)',
    '5.2(1)SK3(2.2b)',
    '5.2(1)SK3(2.1a)',
    '5.2(1)SV5(1.1)',
    '5.2(1)SV5(1.2)',
    '5.2(1)SV5(1.3)',
    '5.2(1)SV5(1.3a)',
    '5.2(1)SV5(1.3b)',
    '5.2(1)SV5(1.3c)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^3[0-9]{2,3}")
{
  version_list = make_list(
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
    '6.0(2)U6(10a)',
    '7.0(3)F3(1)',
    '7.0(3)F3(2)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
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
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(2t)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.2(2v)',
    '7.0(3)IC4(4)',
    '7.0(3)IM7(2)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '10.1(1)',
    '10.1(2)',
    '10.1(2t)',
    '10.2(1)',
    '10.2(2)',
    '10.2(3)',
    '10.2(3t)',
    '10.2(4)',
    '10.3(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^7[0-9]{2,3}")
{
  version_list = make_list(
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
    '6.2(24)',
    '6.2(24a)',
    '6.2(26)',
    '7.2(0)D1(1)',
    '7.2(1)D1(1)',
    '7.2(2)D1(2)',
    '7.2(2)D1(1)',
    '7.2(2)D1(3)',
    '7.2(2)D1(4)',
    '7.3(0)D1(1)',
    '7.3(0)DX(1)',
    '7.3(1)D1(1)',
    '7.3(2)D1(1)',
    '7.3(2)D1(2)',
    '7.3(2)D1(3)',
    '7.3(2)D1(3a)',
    '7.3(2)D1(1d)',
    '8.0(1)',
    '8.1(1)',
    '8.1(2)',
    '8.1(2a)',
    '8.2(1)',
    '8.2(2)',
    '8.2(3)',
    '8.2(4)',
    '8.2(5)',
    '8.2(6)',
    '8.2(7)',
    '8.2(7a)',
    '8.2(8)',
    '8.2(9)',
    '8.3(1)',
    '8.3(2)',
    '7.3(3)D1(1)',
    '7.3(4)D1(1)',
    '8.4(1)',
    '8.4(2)',
    '8.4(3)',
    '8.4(4)',
    '8.4(4a)',
    '8.4(5)',
    '8.4(6)',
    '8.4(6a)',
    '7.3(5)D1(1)',
    '7.3(6)D1(1)',
    '7.3(7)D1(1)',
    '7.3(8)D1(1)',
    '7.3(9)D1(1)'
  );
}

if ('MDS' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
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
    '6.2(29)',
    '6.2(31)',
    '6.2(33)',
    '7.3(0)D1(1)',
    '7.3(0)DY(1)',
    '7.3(1)D1(1)',
    '7.3(1)DY(1)',
    '8.1(1)',
    '8.1(1a)',
    '8.1(1b)',
    '8.2(1)',
    '8.2(2)',
    '8.3(1)',
    '8.3(2)',
    '9.2(1)',
    '9.2(2)',
    '9.2(1a)',
    '8.4(1)',
    '8.4(1a)',
    '8.4(2)',
    '8.4(2a)',
    '8.4(2b)',
    '8.4(2c)',
    '8.4(2d)',
    '8.4(2e)',
    '9.3(1)',
    '8.5(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '7.0(3)F1(1)',
    '7.0(3)F2(1)',
    '7.0(3)F2(2)',
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
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
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '7.0(3)IA7(1)',
    '7.0(3)IA7(2)',
    '7.0(3)IC4(4)',
    '7.0(3)IM3(1)',
    '7.0(3)IM3(2)',
    '7.0(3)IM3(2a)',
    '7.0(3)IM3(2b)',
    '7.0(3)IM3(3)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(5w)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '10.1(1)',
    '10.1(2)',
    '10.2(1)',
    '10.2(1q)',
    '10.2(2)',
    '10.2(3)',
    '10.2(2a)',
    '10.2(3t)',
    '10.2(4)',
    '10.3(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^5[0-9]{2,3}")
{
  version_list = make_list(
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
    '7.3(6)N1(1a)',
    '7.3(7)N1(1)',
    '7.3(7)N1(1a)',
    '7.3(7)N1(1b)',
    '7.3(8)N1(1)',
    '7.3(8)N1(1a)',
    '7.3(8)N1(1b)',
    '7.3(9)N1(1)',
    '7.3(10)N1(1)',
    '7.3(11)N1(1)',
    '7.3(11)N1(1a)',
    '7.3(12)N1(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^6[0-9]{2,3}")
{
  version_list = make_list(
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
    '7.3(6)N1(1a)',
    '7.3(7)N1(1)',
    '7.3(7)N1(1a)',
    '7.3(7)N1(1b)',
    '7.3(8)N1(1)',
    '7.3(8)N1(1a)',
    '7.3(8)N1(1b)',
    '7.3(9)N1(1)',
    '7.3(10)N1(1)',
    '7.3(11)N1(1)',
    '7.3(11)N1(1a)',
    '7.3(12)N1(1)'
  );
}

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd00653, CSCwd18009, CSCwd18011, CSCwd18012, CSCwd18013',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
