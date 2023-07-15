#TRUSTED 55a83c7aa5a063f80a6e4247ff4ad7150d1cf7ec62a08cfa61d4c03aabc5c1df34e75aae559daab428f00ec7b1918b47e2eb42a462e3e54c74096b07ae936f073038f02840e5c3d9a2f01011e46467e4084e5cfe81be874545cee2e3096d60f8d15ee5923b3e5b397ebc48538a067c55c8e4228dbda215063bf0eb5e26fbaa9829056fe9a6ab168776843f03ee4cec67ba4a21dde14eb55ecbf9e2fb8ed150ae73fbe52a4aa67fa6d02b5cf9ef286809a854c9cbed179342e727e084d9fb07da53a751f0a00f5a663cd61bcc5873044294351a73adbb438c847fb82c12218137c905ad961660a07793cc3e286792ab5d73a9bafac337466ce90d3b66a6888f844aa7f027171a12164de7a5a55c0e10f29de6ce679f160633b7ceaf8e108b3ad21a848d42726243a217bfd91941dd929a318c936bb1d24574680aace2aa9635a7d88cb230afe7d1bb1b6865e552c811d5a4c2d8fb74eaeaed0762fbf07239080c35606681ca2806e0881a3e2af7e58220dac67a4ce60c8bef5b90a4d977f260639a64aeb45c594c5126ecbf4e753ebf26eb162f46ecc7ffad0195d0011953d5eb4cf610e0ed5c37af4d070462649f54aa32c94f36c151bb5aee79b4df5cbeab7ff280237337c5e9ad765a7b98f3bf3c349dda938ed7c0db7ca177f82711f9df02f0637246585ea7f145693d14d7402354dbc51fa0b289eec3df7d7ec583bdbb4a
#TRUST-RSA-SHA256 7ade0c36cec0caebfc5259a2c5220fbee58b05d0d2f8175e0ee904870b478b2039ddccfed30dee9b1c7e8e7c159310e97cc9428be997e4788c81100803fa18d8e41dc311ee4f4c575baad0302e93828319a47e6dd8e8828278d757dbe9b2174c494bec14a67a8205b1b60bfdaadc6d85e2af8048a2508589341281316e5bbdaf82ad7414fc82c626330c268972b06a189f43905a21add8c618fcf665f6438396a0a34c7e7fe9288aae82014e95f922f4e99b902cd98ecb23899a13cfeb13e50c6be058f141e519a9b7e30d41a906e9c558806d6818362beefa0e8ad166aae3f6ad44a1849fe8511eb780590fb061625c9d8e426ca84c19e017719513ebbe34ae6ca9696c29447cc3a4cc407eb99276c86389bde596143c5139ed230798ad6725b99de07c086aa3b55a1f0599287520e9f56ab2c9f480438ba7124fe3007a0452050c81242a4a330586d802be4761ae3a275aa3425a9a2fde00f1a82f04397cf3987b67af0e27d016d963ba587f9eb717f9dbbff8604eed835b247c4f154cc5d10f1bb129d0d0e4538c67ff995f23eb83164e75a784b24b369ac6c9caf69a1d320bcb04450b19cb025c18a51a2de2a2d92a8311ba71b3a6ae2d6a6e209610f5e14907021e85cf42d08f8af8745c0ca71cade085ec57dafdeea0142144adfbfa676fb84ef89302a552c63e69b7822ad2c44a9d0bebb9578914b2a2578f762bee23
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131187);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-6663");
  script_bugtraq_id(99973);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd88936");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170726-anidos");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS Autonomic Networking Infrastructure DoS (cisco-sa-20170726-anidos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the
Autonomic Networking feature. An unauthenticated, adjacent attacker can exploit this by replaying captured packets to
reset the Autonomic Control Plane (ACP) channel of an affected system in order to reset the ACP channel of an affected
system, causing autonomic nodes of an affected system to reload and stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-anidos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89580ea2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd88936");
  script_set_attribute(attribute:"solution", value:
"No fixes are available. For more information, see Cisco bug ID(s) CSCvd88936.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6663");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '15.3(3)S2',
  '15.3(3)S6',
  '15.3(3)S1a',
  '15.3(3)S5',
  '15.3(3)S7',
  '15.3(3)S8',
  '15.3(3)S6a',
  '15.3(3)S9',
  '15.3(3)S10',
  '15.3(3)S8a',
  '15.2(3)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3a)E',
  '15.2(3)E3',
  '15.2(3m)E2',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(3)E4',
  '15.2(5)E',
  '15.2(3m)E7',
  '15.2(4)E3',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.2(3m)E8',
  '15.2(3)E5',
  '15.2(4s)E2',
  '15.4(1)S',
  '15.4(2)S',
  '15.4(3)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(2)S1',
  '15.4(1)S3',
  '15.4(3)S1',
  '15.4(2)S2',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(1)S4',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(3)S0d',
  '15.4(3)S4',
  '15.4(3)S0e',
  '15.4(3)S5',
  '15.4(3)S0f',
  '15.4(3)S6',
  '15.4(3)S7',
  '15.4(3)S6a',
  '15.4(3)S8',
  '15.5(1)S',
  '15.5(2)S',
  '15.5(1)S1',
  '15.5(3)S',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(3)S1a',
  '15.5(2)S3',
  '15.5(3)S2',
  '15.5(3)S3',
  '15.5(1)S4',
  '15.5(2)S4',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)S6',
  '15.5(3)S6a',
  '15.5(3)S7',
  '15.5(3)S6b',
  '15.5(3)S8',
  '15.5(3)S10',
  '15.2(3)EA',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(5)EA',
  '15.2(4)EA4',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.4(2)SN',
  '15.4(2)SN1',
  '15.4(3)SN1',
  '15.4(3)SN1a',
  '15.5(1)SN',
  '15.5(1)SN1',
  '15.5(2)SN',
  '15.5(3)SN0a',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(2)S2',
  '15.6(1)S3',
  '15.6(2)S3',
  '15.6(1)S4',
  '15.6(2)S4',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T0a',
  '15.6(2)T2',
  '15.6(1)T3',
  '15.6(2)T3',
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SP2',
  '15.6(2)SP3',
  '15.6(2)SP4',
  '15.6(2)SP3b',
  '15.6(2)SP5',
  '15.6(2)SP7',
  '15.6(2)SP8',
  '15.6(1)SN',
  '15.6(1)SN1',
  '15.6(2)SN',
  '15.6(1)SN2',
  '15.6(1)SN3',
  '15.6(3)SN',
  '15.6(4)SN',
  '15.6(5)SN',
  '15.6(6)SN',
  '15.6(7)SN',
  '15.6(7)SN1',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M7',
  '15.6(3)M6a',
  '15.6(3)M8',
  '15.7(3)M',
  '15.7(3)M1',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M4',
  '15.7(3)M5',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M5a',
  '15.7(3)M6',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M2',
  '15.8(3)M3',
  '15.8(3)M4',
  '15.9(3)M',
  '15.9(3)M1',
  '15.9(3)M0a',
  '15.8(3)M3b'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['autonomic_networking'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd88936',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
