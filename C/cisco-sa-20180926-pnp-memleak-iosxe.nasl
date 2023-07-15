#TRUSTED 32e9e2c2b2bbdc569304de06b239c16a6015a0f6ae225a178c291352668a481010796772ff178026a41db10ef64574ff3ac29b1d677bf32f0f5331873845873fbc7165ac50bc314e8e4e96d47ef5812b6d3e7e40ec41ffcfdf146b486058c676518165b2bfe545d919558c0934ead6b627c77146379572f3e52db2619b3af44fe02be3324a581d76e30ac7e022fe61ebd5d5f7db900254a22524a9f2b9e7a43f8f4ef4b38a5f2941fae02490b49108cd8c90a4a7f0abd4bfbb669407a04c5e474e16c6e18e16704d7887baa5a5b0e48d7a60899e4f038765b15e6c5b8025247a134493a2a7ba00eaa617231da038815bfb415535665a95ec04d4738741e8391feb5bcd0216bca922bf98ceaabdeeed49fe84d8056983291ad6236ad7944a8322c4b0a23284c8f4f13d30926c5f4747df19bd0dac974cfd26a4c84098f1dab770ec586c757fd6d1667d6ff17d4294eb5ae47ff16af8edafa2a9c25b9e42106296b4fd41b58ea3f3997c98d0786dd0753046d1154d85a641992ffaca7218a21d937181723cae40e606c8289addaced5b9f175ac257a0b81e99a840a76b1caaf84238e085d67509f7dd71ed4826947f40d3af77b63df767d689e766a3a4a5a64dc7f8461149649cab9f114f6f6890c7def8afb377224f9b28017fdb5b7d3c92e02f3ae6339f42e346cd4931e2b50b3ebe7c2ccd0d0da1552142d89d2e99924230c7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132049);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-15377");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi30136");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-pnp-memleak");

  script_name(english:"Cisco IOS XE Software Software Plug and Play Agent Memory Leak(cisco-sa-20180926-pnp-memleak)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a memory leak vulnerability in the Cisco
Network Plug and Play agent due to insufficient input validation. An unauthenticated, remote attacker can exploit this,
by sending invalid data to the Cisco Network Plug and Play agent on an affected device, to cause a memory leak on an
affected device, causing it to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-pnp-memleak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f91b535a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi30136");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvi30136.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '3.10.0E',
  '3.10.1E',
  '3.10.0cE',
  '3.10.1aE',
  '3.10.1sE'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi30136'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
