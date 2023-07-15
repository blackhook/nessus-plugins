#TRUSTED 2053666d3b1ff22de4a960069fb0538b10b6af6a3573ae5ec66d4f548f6ee074f59e0f8526b61d30cef0af0c0c75488777efe74f9ee6c1a3a50bd3477365896d6ef08bf95f4a3f721ca31a2a03539826493875594dd715f1e1731ca121b88eb56f3c89ade0cdd31c992521ff2848aa7786f5673d325c998115bda37e1d4bc8b9f319473459db54a6c3fa7a50fa0cf0945ebc72fdf1b39560aa2e468a487b84fbb3809cf9f2e3636c4e0941de66af768c4c9e5481497f2aa9d90e4e6e2d26c049ad2dc990a09a20e525a7cd4986ea3d272eb7e56f0728e6e46a9fb699bbfe69482295afba73c0fbbe638d5c0e43b562c654e114a67f14bc39508115d7205a91e1669cefae703c96548d30370f951ebb8bec76d239c9083d1f9d0434b99c5d05713734bd6871c58fbe0cf08f88d596c6f224061f7b4b665d515d44c55bbd758436319527c6d64d5c4db3a99c92e71f9862c38311888ff05d18d7f51d5d0a4732a75aa20e10e882692e21d3f8a8db915ea5ee6dac60c7362d47c903004cd69e5986906494448e8aa94110ad8c87782c1ad6774ff79ab2d7945ab0c587e8ee41789cd744480881bf8bba37ae1bdb8f8935c10da4103c09d3b7dd677c7827ec7381b2c96d1222c63e077fc998604556ffcafc5ae44f7c2bca82ec61bcfeba4faca61e3fd69eb36f2bc0d6983e7469e4937968b1ba4e120d7b427adeccdca430672db1
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153153);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1385");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw64810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx21776");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx21783");
  script_xref(name:"IAVA", value:"2021-A-0141-S");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-pt-hWGcPf7g");

  script_name(english:"Cisco IOS XE Software IOx Application Environment Path Traversal (cisco-sa-iox-pt-hWGcPf7g)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Cisco IOx application hosting environment of multiple Cisco platforms could allow
    an authenticated, remote attacker to conduct directory traversal attacks and read and write files on the
    underlying operating system or host system. This vulnerability occurs because the device does not properly
    validate URIs in IOx API requests. An attacker could exploit this vulnerability by sending a crafted API
    request that contains directory traversal character sequences to an affected device. A successful exploit
    could allow the attacker to read or write arbitrary files on the underlying operating system.
    (CVE-2021-1385)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-pt-hWGcPf7g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?529bd81f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw64810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx21776");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx21783");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw64810, CSCvx21776, CSCvx21783");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.2',
  '17.3.2a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['ios_iox_host_list'],
  CISCO_WORKAROUNDS['iox_enabled']
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw64810, CSCvx21776, CSCvx21783',
  'cmds'     , make_list('show iox host list detail', 'show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
