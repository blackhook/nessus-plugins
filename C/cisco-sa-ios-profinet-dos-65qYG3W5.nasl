#TRUSTED 994d088374cac9a1f5e21f26164faa399fd8c87575311ee36c5b12a2aafecf5073e288a2bdfc3e81cec2f5eb949fd5caecee3ea54091bf1fa57d2914a81ebbd340d7c9e4224b464153c06bb3858de7aef7b95a2f288ca0b7faaf11aeeac09e3d53a13460f77d18f650735bfb076ce7670c2aec80fa56b19bbb7f0ae84ee81d8458cfc8678c9a965ed99f8cbd3fc74cddf252e0118e832bc8476a505ad6809a27ca33e44b4143aff872bc683c566e893495bcfba53d1c61f3fd93396a5b81fcd8e57654ce4b5c9b4c91d0192bba9fbf4addcc92e70edd49939cf8f46e20b587107ec1200ed6a693ced8a9d161e4ee61be4169c63086f377bba0e8278a6bd44bc83c9ead9b388a1d4f9bfee1081be52238426555ad9aecae35cc21c8fbdd2b3f9cd11e6ac61a5522681eb0817028a57bbe47adf233865253d933fb91da20d9ba9041e4f7135a1386c446975fc7d479afe1a4bd376efdf2337195e865a89a02dbf2d5c858aa0763173f6aa43c8e76ddc690d0fa3bebdeffa1348c765451238852275832203d65ae1466aa12b67e9c91e5a40b8816634f6c3113a9963b6a0085abdc9daba03e2cc00f3ac3d56abe8235beb2c349f82804c173742db52b00f50035268a487998e51f8ca435f956e4a3ae244dbae477078756f5b1d8114a651109796d01452ec938d38a8e06a057b16f1b18a4126e5898029a1f8ca1fc60b19ddb7b88
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142959);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2020-3512");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr54115");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-profinet-dos-65qYG3W5");

  script_name(english:"Cisco IOS Software PROFINET Link Layer Discovery Protocol DoS (cisco-sa-ios-profinet-dos-65qYG3W5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco IOS software running on the remote 
device is affected by a denial of service vulnerability in the PROFINET handler for Link Layer Discovery 
Protocol (LLDP) messages. An unauthenticated, adjacent attacker can exploit thisby sending a malicious LLDP 
message to an affected device to cause the affected device to reload.

Cisco has released software updates that address this vulnerability. There are no workarounds that address 
this vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-profinet-dos-65qYG3W5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aaa4e06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr54115.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3512");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '12.2(6)I1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E2b',
  '15.2(6)E3',
  '15.2(6)E4',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0a',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7a)E0b',
  '15.3(3)JF99',
  '15.3(3)JK99',
  '15.3(3)JPJ'
);

workarounds = make_list(CISCO_WORKAROUNDS['profinet']);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr54115',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, reporting:reporting, vuln_versions:version_list);
