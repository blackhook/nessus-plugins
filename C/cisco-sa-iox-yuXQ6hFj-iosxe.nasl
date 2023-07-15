#TRUSTED 9cf17f97843e72a825efd3ed86f9fbe9516176d9e947610cd8aa98c62001c218530a2ffdc6d4780e05c3fcd97d90afc3a3deef19475975c6b85d81486588dcc8eee55c41474d5f2a4604103e3926a5bc0bc5f90f4ef2f56858b82b0bec702d455675f3190c81f7365014e1128b60d901727616e81ae33d36c12c9632541a3a8699e3414040000774bf7d3e525506144e7eab54e8f301685efa161689260b1531364dabed8407a30ed9c4dd0bfd7df4b8cec67714ed67b2c60e541e518bd90d96e29993b10d31bdc27d2e30d26bdc2efbaf9f213cc2f1ce4ddb4d25a40499bbb842790b88aea7065b7312f02da76f075cafbbed0f890d23193e381bdc16cfa464b69c4435de92078fdae1d8407ece6279f9b37cd262c7f28d08692c68e734388cb4d6b024d6015ff4f12ff5e1f6dcab57414b20377ef5209f03c9b382744e07cfb49cc0336eac474946a42d0cc90c9feccc4a3464e9ecba008c277afb6ec60cabeb247dd23f08325620c2848133f23333c92d5fb1d78f58fa4053f3721c97b521044a4ed262811ceabcd1a4024aea24d8aa52df1565e6e7f01e7e334f9f8631ff4e5ae85d00440215726e7523901ae80dcb80ebb91a295366f5ce0cefab91835fba445e2075bed5ab59ff32a3e3cd20fcacb065a01e203dc3675da714f32b524161d86ea214e97f877f5245608aec7243a2ff67c7f807aad79c7b0f2a99513dfb
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160083);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2022-20677",
    "CVE-2022-20718",
    "CVE-2022-20719",
    "CVE-2022-20720",
    "CVE-2022-20721",
    "CVE-2022-20722",
    "CVE-2022-20723",
    "CVE-2022-20724",
    "CVE-2022-20725",
    "CVE-2022-20727"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy16608");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy30903");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy30957");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy35913");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy35914");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86583");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86598");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86602");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86603");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86604");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86608");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-yuXQ6hFj");
  script_xref(name:"IAVA", value:"2022-A-0157");

  script_name(english:"Cisco IOS XE Software IOx Application Hosting Environment (cisco-sa-iox-yuXQ6hFj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by multiple vulnerabilities:

 - Multiple parameter injection vulnerabilities in the Cisco IOx application hosting environment. Due to
   incomplete sanitization of parameters that are part of an application package, an authenticated, remote
   attacker can use a specially crafted application package to execute arbitrary code as root on the
   underlying host operating system. (CVE-2022-20718, CVE-2022-20719, CVE-2022-20723)

 - A path traversal vulnerability in the Cisco IOx application hosting environment. Due to a missing real
   path check, an authenticated remote attacker can create a symbolic link within a deployed application to
   read or execute arbitrary code as root on the underlying host operating system. (CVE-2022-20720)

 - A race condition in the Cisco IOx application hosting environment can allow an unauthenticated remote
   attacker to bypass authentication and impersonate another authenticated user session. (CVE-2022-20724)

 - A cross-site scripting vulnerability in the web-based Local Manager interface of the Cisco IOx application
   hosting environment can allow a remote attacker, authenticated with Local Manager credentials, to inject
   malicious code into the system settings tab. (CVE-2022-20725)

 - A privilege escalation vulnerability in the Cisco IOS XE Software which allows an authenticated, local
   attacker to elevate privileges from level 15 to root. (CVE-2022-20677)

 - A privilege escalation vulnerability in the Cisco IOx application hosting environment due to improper
   input validation. An authenticated, local attacker can modify application content while the application
   is loading to gain privileges equivalent to the root user. (CVE-2022-20727)

 - Multiple vulnerabilities in the Cisco IOx application hosting environment. Due to insufficient path
   validation, an authenticated, remote attacker can send a specially requested command to the Cisco IOx API
   to read the contents of any file on the host device filesystem. (CVE-2022-20721, CVE-2022-20722)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-yuXQ6hFj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6323327a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74561");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy16608");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy30903");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy30957");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy35913");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy35914");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86583");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86598");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86602");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86603");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86604");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86608");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvy16608, CSCvy30903, CSCvy30957,
CSCvy35913, CSCvy35914, CSCvy86583, CSCvy86598, CSCvy86602, CSCvy86603, CSCvy86604, CSCvy86608");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20723");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-20724");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 77, 250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# No model check as all devices with IOS-XE considered potentially vulnerable

var version_list=make_list(
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
  '16.6.9',
  '16.6.10',
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
  '16.9.7',
  '16.9.8',
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
  '16.12.1z1',
  '16.12.1z2',
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
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
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
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.6.1',
  '17.6.1a',
  '17.6.1w'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['iox_enabled']
);

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'flags'   , {'xss':TRUE},
  'cmds'    , make_list('show running-config'),
  'bug_id'  , 'CSCvy16608, CSCvy30903, CSCvy30957, CSCvy35913, CSCvy35914, CSCvy86583, CSCvy86598, CSCvy86602, CSCvy86603, CSCvy86604, CSCvy86608'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
