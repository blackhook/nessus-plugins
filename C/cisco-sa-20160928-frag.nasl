#TRUSTED 34e7cfbecc9ae0c6e40677de95c119af59750079b3f7ad5d6331f34ca7aa6c7958c5ce6d4aadb6729ad611cd3506d199fcc45c32e3f8056264430dd5a4cbd2dc1f4acc51cbfc1085991071bd07ac020a05208fc5d5e3d23e12c8cb2fb0de5b032982c76fa4b5fe60e486d5c0bbd753fe6b18f80b296a45ef396ebd377ac8e66e9666b32d0defce6a356a77b208e61aa1ed33b35e6e16c494f06f261160d74ad8ca66ae1bf206131ddebbe28c00e52e6825101cca5c0e677c8ebf5b468f0a0d3e34617b4e73a773b01dd0452d0fe26151aeae48902f8e67bc42a5beede7ba5cc4617cbee6b919f31c2eb79a1fbec3559e02bdcb27de53d470ce868564baf8104a55133730a23792520c532fa9c00fc8d301210cde26484231c84499755d9553179617d735fb5c06bcca152a2ff4bc70013aeef6c5d925add3dea898478d0bc27de56c979752581f52dd42f3df3e4ca5d1d0e196755d99425a669394f82ee0b12839921982053086a9d0969718034a9b341c910e2dbd3fd38d09c9016b36c73f0dad4d21414add588217518ac4685a62f43ab5da00c41a9d77b146338b61376baa08ed9d4417986c2842fab3a1f66e29d44897ff1317c8b018a44a8af1100420c1fc7ab0f23b59a33ec46b2de3722a7db81b4d672e62668ae2e039044283c96bb7927646e960a0a13395a2795ec94e8c156a809cd09fcaee47cae05bc5f715770e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130971);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2016-6386");
  script_bugtraq_id(93202);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux66005");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-frag");

  script_name(english:"Cisco IOS XE Software IP Fragment Reassembly DoS (cisco-sa-20160928-frag)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the IPv4 fragment reassembly function due to the corruption of an internal data structure that occurs when the affected
software reassembles an IPv4 packet. An unauthenticated, remote attacker can exploit this, by sending crafted IPv4
fragments to an affected device, to cause the device to reload and stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-frag
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62f9a0ef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux66005");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCux66005.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Only 64 bit devices are affected
show_ver = get_kb_item('Host/Cisco/show_ver');
sys_desc = get_kb_item('SNMP/sysDesc');
if ('X86_64' >!< show_ver && 'X86_64' >!< sys_desc)
  audit(AUDIT_HOST_NOT, 'affected');

version_list = make_list(
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.7.1aS',
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.0xaS',
  '3.9.1aS',
  '3.9.0aS',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
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
  '3.13.2aS',
  '3.13.0aS',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.2xbS',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.5.3SQ',
  '3.5.4SQ',
  '3.5.5SQ',
  '3.5.6SQ',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.0cS',
  '3.17.0S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '3.2.0JA',
  '3.8.0E',
  '3.8.1E',
  '3.18.3bSP'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCux66005',
  'cmds'     , make_list('show version'),
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list);
