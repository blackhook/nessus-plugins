#TRUSTED 88ffab3faa5ac38f9da5ecc412c5c4e97d90654104a8dd4f8cb19d0b4b4ac3cf7fe34d09b72e63f6f57022374ece6fd865a4b5066b11dded1f323ed1f3b5e17bec6bfa2cfc87923503adca6538e4afd8f399da6183d190d131caed745a2d89c5864316c7c45a5d2589ceff278b227dc92a79aeccd053c7f0917635c34a44a04f0d4040c604cbe835a2c08887f58242a56a5b9025dd9845d5965ac885f7a988482f16c9cf83fc76cc5e88708a8ea6d4fe883050809adde0f326ff9c1be50cf5151c953f883247521b9f5ebed18789e9fe368a84b01a21556642e35dc86d9b0a39b19ccd4cb7718e52e34a78994eb0d1438e415902e59d79791c26ef4d54e0e917bc9fc9324e3daed726959e88a80b97c14f381ec8bd55dc0ae3c336b1c528738ffb8d3b32bf22223adac60fdad93aed14c13fe12886cc27493cba42348cdfc94d20355e42fb8dcd9d70ba781b3a76bdc9082464c1b5706b3e9f30e759aca6e131b058d4ef6162cf5258edf9a7bb5ce2c87894a730f402f10b664f64127dfadca39baa10d13bf55336b036fde2a6237a20b6baab13b308b33a58fe8d65ede8ca3663ee2471f89fca502d02e322f3ba770a0647f57a020628d39a8401a8781819c68e5630376c1ad54557b59ff55e707a28a0a8ee71d77ed1f8fb78f828cb081a4e972c4bb73cc5dba252042097e09969266961bc98c3cda73dff511b4f9a999c70
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148107);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1442");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt41030");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-pnp-priv-esc-AmG3kuVL");
  script_xref(name:"IAVA", value:"2021-A-0141-S");

  script_name(english:"Cisco IOS XE Software Plug Play Privilege Escalation (cisco-sa-ios-xe-pnp-priv-esc-AmG3kuVL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-pnp-priv-esc-AmG3kuVL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e65821f");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt41030");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt41030");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1442");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(532);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.6E',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.6.8E',
  '3.6.9E',
  '3.6.9aE',
  '3.6.10E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '3.8.9E',
  '3.8.10E',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2aE',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.2bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.16.10aS',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2S',
  '3.18.2SP',
  '3.18.2aSP',
  '3.18.3S',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4S',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
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
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt41030',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
