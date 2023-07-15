#TRUSTED 85c042e7403dc80a74224ba1f01300a1f24d1661702b5a5eaa3c9642a9779eda50567601e6dfc4b69314c25737a9e7b052e9068a1aff4089244ac17e1d0ded1ce2af25a462fd55ddb8812389038ce1265d7607d6d00ceed73d905a10329203edeed53a62ced774d9c96a4446aefab3f50594c6abe97e03fd1e444dae00ea6e52835332bd761d6917643087d96caaa73f6b8d9389cd2e2baf5cede5150a752205eaa3daa85115117f7aac899727f2c02f7e38ee3c1b52e820a39b860afc480530f69bd8456f9a54f825180efe49ccce82edac818bef7af94ba5054f243e764f3e458199a7021b5f6a6e4c05182149683d777c7c089ee073920bbaf6d929459ca112072e9d6f36c6922e151fd1edafe0109724e38c10c4433fadeff09f3c7224705c3c10de1ddb55b85a33b95fc8a524728ab03d57698ba996eb1e6525b2f643cf589a8fcecc08e71c44f3f8fea0e621afb28aea9b391ccba7f629f9bb95df0e5292f9dcddf96a8018df9c349ec68c4e78b608c763fc27f271c5522a4586bfd5dd6ee3a2150c2f2ec56f14a5e22f47239768394df8bc9a931d1eddbe429d0166ef6e2ae3bf37bc3ec5a370f51ab316051f582cc37550714206a5df4dbeb01c5395d35df46051ae4e55ad21fd7e11cd0f8346523b19a63b02d1e7648bd05b7f6b74e241939db1fc2f429de494c61088926d14fc53146ceb96e45faa03cd63246ae2
#TRUST-RSA-SHA256 a07bc70b1a24d278ddade0cc3214631ebc1e64ff36de158ed87441f8ee0a2c77f643e4a2ea0b0d4400512e2891394dda011cdf2d8a88b9a16b50d5db71575a14a1e1780fba8cdbe35a8756a654c6f74b6a82f96330bf7d0c3a61728ca035ef8a996c3f1a7d1f8d8c8f85d6628d50d1a037ed3fb00dc6a42252e57ddc7e765b40ccad50ea630c54a74bc2daf0aac9577e8123e4831bb9ba86a89fc6efa74f0e5b4cd79dce34dc0e3632ffd44a40a5340e15a1f5a21d2090f0034dd416bf3806cfb856fc5d17e6be699dd3d123f336d71e7ef2cd783291b1e566afb7bbe6c5183a29118ee7e201b9bb49d9288abfb63ea67aef668680e852e6183dfff9c325fa8e934afbc4de7d18fc04d0c7f9a0ca2fd35a12dfbf185f51c306be361facbf3d87775f4e7725818c839bed180a0fb14713d9f6ada76266dde280197571a0f50eb9d0362862f7e8e52a43d9c8b10c1567301535a90c890aff87d6c4c8b77de9db156354bbc126a02fb12948ea37df2c81b847f5124721a3dc611059d8b409843b517a5dc6ce6cd94f290796f4a40f02fd306e47684e71c4df4e570d0166523abd2ec7d5605be380c5419e34e673f19f006ba3ed2649c1bcc57b3b27e83b7d869b6ee61e13b90bd3ca553a264d8c4f1410f3e4abc1e8d75edb02dc40c7969bda8e7d4427ceb40f60a697ba428ae7789b0d4d89e9cedf01758bfdb76b20963dcfdd6d
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131188);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-6663");
  script_bugtraq_id(99973);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd88936");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170726-anidos");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS XE Software Autonomic Networking Infrastructure DoS (cisco-sa-20170726-anidos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Autonomic Networking feature. An unauthenticated, adjacent attacker can exploit this by replaying captured packets
to reset the Autonomic Control Plane (ACP) channel of an affected system in order to reset the ACP channel of an
affected system, causing autonomic nodes of an affected system to reload and stop responding.

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.10.4S',
  '3.10.1xcS',
  '3.10.8aS',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.7aS',
  '3.13.8S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.9.0E',
  '3.9.1E',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.9.4c',
  '16.9.5',
  '16.9.4d',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1e',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.2',
  '16.12.2a',
  '17.2.1'
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
