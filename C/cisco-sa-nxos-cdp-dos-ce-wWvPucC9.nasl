#TRUSTED 0a17a913712436c944a21b558910dda5b14d7ef3c025d9c152e16398f51ac015e48b65fe63e588dd7a996615f262cc6bedf0dc60a275b858a99c60e5fb968be7f5a9cf94fe984de59ce1559b06a8cd7bf21d36de598092c1892420b8b8cb070521752de01c0394753e378fb8e89441f8da5accf375ff44a08a8ce75c88d6c2ac8e188481a6f0c25c7e8cf704174fc4a22843e793c7eb6dc224e5f08227900478652df2749ac615ff1b22467260f1d81ba55f5331883c71f23237f58e2e4f62a73db9aff94f3127b481be52205e7466f503fc5661c1e4db76767110d8a4f25f0fe27811182117b3c1393f5bc983d1dd6b101e3cee8a3754f97f392a2faecd5f78fde22289acfef7a3e2b1771ece914848ed80f02e01ba104c2be1d79e1eb88616edc91f5345600bc008b55615b4fd80416d8f9bc7d6c4063b2a1176625d7766684a94ac85bc5b0b53e47778f225a27ba2bb048db68c51f4c3a3e53004fae9ea61c74677b4f94fc583fb0005337a4a1fbe0704e267b0b969d72d39c6cf8da926cbb6c36cd82131275ac513c80f069420fced317b2e7f2018c5ab97f240571e00c3993131314c2579c3f99104e5264b2be3f5efe8c1267fa29b85a19e0a589b98dad6b39137a57629a15213b643bc008d2d5dd711d3f57e10074a64c941665aca633e1decfde53b5e7176bcd9d50d8aeed80eefbe1e18ee4025598d006a69f134c7
#TRUST-RSA-SHA256 21a56171e8c8c324013309fc3034afb577159e37cd77d617b15587f5c8c9b0b2250471d3d6716085de0315a097087704a09536c8f7d8aaabd1b6f24277d24518d43c842b3ad9b9bad4ffc73f7ed94ba179b15641fad3264b8e80a6d0eadb72b92ea3596db61dcc1bc491250c2369876ac53e2211edc6c5d6cf2822d1427f49d6ea0cd810a07b7026ccb1bee3851a2ea0a77917496eb98ef45f5fbcd6ced5e87934bc625989f2f0c4e1ef718ba5beed1531dea95ece6a471d640bea4c3ec3286c57b1d6b2a9337176ce9dde9a06616095239170a1b700f7c90f9efbc12b8797011e342e28b6bb0e4c1a26ba897da9541d797d20aa38a7f88bf5f9c1f611f6f197ee20bbf1b2adcbb2876a0731ba816f5bf3df772fc3739a25dbb77071e3eda84ef304fa6946b850f01e9954683075c2ab99a11af1211bf13010cf9990e0092c74bbc32607b19bbf82558a3986f06ddaa779337c40c7d822bd9f2e9e5b5471a7545e454aabe4c4f00c018cf58929865bd774c37f0ddd0b43bd91b8b061434d10e370967970ac6aa5bb463c04f68fb3a7022b9ce603f1826503d3ea34762ae7b844b2c1671874c789e1b2ba609eba45fabcd76fc403b6197129fb87be6ff6fbd0ea6398d643b7d3fbc2b7fb814dee8cffda967998ddd3b5c1afe3fdd444c58ea20cb24a8064ceead1603934096dd29e3fc24bd7e1e4a411a9e453ae656bf6047daf
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164453);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2022-20824");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb70210");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb74493");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb74494");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb74495");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb74496");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb74497");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb74513");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-cdp-dos-ce-wWvPucC9");
  script_xref(name:"IAVA", value:"2022-A-0343");

  script_name(english:"Cisco NX-OS Software Cisco Discovery Protocol DoS Arbitrary Code Execution (cisco-sa-nxos-cdp-dos-ce-wWvPucC9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software with Cisco Discovery Protocol enabled is
affected by a vulnerability due to improper input validation of specific values that are within a Cisco Discovery Protocol message.
An attacker could exploit this vulnerability by sending a malicious Cisco Discovery Protocol packet to an affected device. A successful
exploit could allow the attacker to execute arbitrary code with root privileges or cause the Cisco Discovery Protocol
process to crash and restart multiple times, which would cause the affected device to reload, resulting in a DoS
condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cdp-dos-ce-wWvPucC9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a67afe3a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74837");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb70210");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb74493");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb74494");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb74495");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb74496");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb74497");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb74513");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwb70210, CSCwb74493, CSCwb74494, CSCwb74495,
CSCwb74496, CSCwb74497, CSCwb74513");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20824");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var is_aci = !empty_or_null(get_kb_item('Host/aci/system/chassis/summary'));

if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])1[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])3[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])7[0-9]{2,3}") &&
    ('MDS' >!< product_info.device || product_info.model !~ "^9[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])5[56][0-0]{1,2}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])6[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}") &&
    ('UCS' >!< product_info.device || product_info.model !~ "(^|[^0-9])6[2-4][0-9]{1,2}"))
audit(AUDIT_HOST_NOT, 'affected');

var version_list = NULL;
var vuln_ranges = NULL;

if ('Nexus' >< product_info.device && product_info.model =~ "(^|[^0-9])1[0-9]{2,3}")
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

if ('Nexus' >< product_info.device && product_info.model =~ "(^|[^0-9])3[0-9]{2,3}")
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
    '9.3(9)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "(^|[^0-9])7[0-9]{2,3}")
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
    '7.3(5)D1(1)',
    '7.3(6)D1(1)',
    '7.3(7)D1(1)',
    '7.3(8)D1(1)',
    '7.3(9)D1(1)'
  );
}

if ('MDS' >< product_info.device && product_info.model =~ "(^|[^0-9])9[0-9]{2,3}")
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
    '8.4(1)',
    '8.4(1a)',
    '8.4(2)',
    '8.4(2a)',
    '8.4(2b)',
    '8.4(2c)',
    '8.4(2d)',
    '8.5(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "(^|[^0-9])5[56][0-9]{1,2}")
{
  version_list = make_list(
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
    '7.3(11)N1(1a)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "(^|[^0-9])6[0-9]{2,3}")
{
  version_list = make_list(
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
    '7.3(11)N1(1a)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "(^|[^0-9])9[0-9]{2,3}")
{
  if (is_aci)
    version_list = make_list(
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
      '13.2(3j)',
      '13.2(3s)',
      '13.2(5d)',
      '13.2(5e)',
      '13.2(5f)',
      '13.2(6i)',
      '13.2(41d)',
      '13.2(7f)',
      '13.2(7k)',
      '13.2(9b)',
      '13.2(8d)',
      '13.2(9f)',
      '13.2(9h)',
      '13.2(10e)',
      '13.2(10f)',
      '13.2(10g)',
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
      '14.2(1i)',
      '14.2(1j)',
      '14.2(1l)',
      '14.2(2e)',
      '14.2(2f)',
      '14.2(2g)',
      '14.2(3j)',
      '14.2(3l)',
      '14.2(3n)',
      '14.2(3q)',
      '14.2(4i)',
      '14.2(4k)',
      '14.2(4o)',
      '14.2(4p)',
      '14.2(5k)',
      '14.2(5l)',
      '14.2(5n)',
      '14.2(6d)',
      '14.2(6g)',
      '14.2(6h)',
      '14.2(6l)',
      '14.2(7f)',
      '14.2(7l)',
      '14.2(6o)',
      '14.2(7q)',
      '14.2(7r)',
      '14.2(7s)',
      '14.2(7t)',
      '15.0(1k)',
      '15.0(1l)',
      '15.0(2e)',
      '15.0(2h)',
      '15.1(1h)',
      '15.1(2e)',
      '15.1(3e)',
      '15.1(4c)',
      '15.2(1g)',
      '15.2(2e)',
      '15.2(2f)',
      '15.2(2g)',
      '15.2(2h)',
      '15.2(3e)',
      '15.2(3f)',
      '15.2(3g)',
      '15.2(4d)',
      '15.2(4e)',
      '15.2(4f)'
    );
  else
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
      '9.3(9)'
    );
}
if ('UCS' >< product_info.device && product_info.model =~ "(^|[^0-9])6[4-6][0-9]{1,2}")
  vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '4.1(3i)'},
    {'min_ver': '4.2', 'fix_ver': '4.2(1n)'}
  ];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwb70210, CSCwb74493, CSCwb74494, CSCwb74495, CSCwb74496, CSCwb74497, CSCwb74513'
);

var workarounds = NULL;
var workaround_params = NULL;
if (is_aci)
{
  reporting['cmds'] = make_list('show cdp all');
  workarounds = [CISCO_WORKAROUNDS['generic_workaround']];
  workaround_params = [WORKAROUND_CONFIG['aci_cdp']];
}
else if ('UCS' >!< product_info.device)
{
  reporting['cmds'] = make_list('show running-config all');
  workarounds = make_list(CISCO_WORKAROUNDS['nxos_cdp']);
}
else {
  # CDP can't be disabled on some UCS ports so we'll determine it to be always vulnerable
  reporting['disable_caveat'] = TRUE;
}

var smus = NULL;
if ('Nexus' >< product_info.device && !is_aci)
{
  if (product_info.model =~ "(^|[^0-9])7[0-9]{2,3}")
    smus = {'8.2(8)': 'CSCwc36631'};
  else if (product_info.model =~ "(^|[^[0-9])[39][0-9]{2,3}")
    smus = {'9.3(9)': 'CSCwb70210'};
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges,
  smus:smus
);
