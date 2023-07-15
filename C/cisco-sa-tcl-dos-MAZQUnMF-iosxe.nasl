#TRUSTED 53377e5cd5c844890f97d84c6d78bd7cfcda05ac82d8e56c1286e93f6281e2f3d9065c87c9bdec948242d3537dfc32c3ffb5203811dad62cdbfcab9e46ccc87642e473fcee2e75fb6ceaae70ce20c219477fe109c19fd94215f70ec2acee38de0fc56e9c091b20bd3c66cf294d839bcafa38f4443a376dd574a6816ddb3dd8067909268d0391936420f79dc7b84da7e3eb94e5010eb6193341e30eeaef1ee165f009f945d6514f173a671f3ae5c09af384d06420037e61f4fcdd7fbd15b971b2783d356c2d518cbc3acf0ec49d876096d7e6f66103df52898cdc64d9234c85411e78f8c03b9032006b15eee094e1ae241f9c3375a50f434997ba3ca19447fdbf2de545233a1fd0b057214e644c169777d8a646e96ce944ac89060ed3420c22bb561fe6fb3e4d355c0eac1393cfe95a35468ed391536d2b8fbafbdea99f1bc38e55026cc0da08dc16b9c7e6ba002918e1b316cdcd6eadf63dffe6fa8769b699aa5e06a6a45e94459e3b39eda186c77f24561676f229df3840afb47bd7a496569b9f81a0a5dc3c63682c2aac68c4d656afc83bf8fad03315d21da744969031428221b423999902d33f3257c6394f45a854beb3c4328603c21508f5704d8cc6b39ddfdd82336a7305523e98bd08e284437dd8a61f1fe86a4e0a2ee6915fb3414981a4917fd7535b0816ba9569f4c0977195de963d531cd0f9bb4fb6c90d67b9b029
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137408);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3201");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq28110");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tcl-dos-MAZQUnMF");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Tcl DoS (cisco-sa-tcl-dos-MAZQUnMF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a vulnerability in the Tool Command Line (Tcl) interpreter
due to insufficient input validation of data passed to the Tcl interpreter. An authenticated, unprivileged, and local
attacker can exploit this, by executing crafted Tcl arguments on an affected device, in order to cause a denial of
service (DoS) condition on an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tcl-dos-MAZQUnMF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ba71b51");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq28110");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq28110");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2S',
  '3.9.1aS',
  '3.9.1S',
  '3.9.0aS',
  '3.9.0S',
  '3.8.2S',
  '3.8.1S',
  '3.8.0S',
  '3.7.8S',
  '3.7.7S',
  '3.7.6S',
  '3.7.5S',
  '3.7.4aS',
  '3.7.4S',
  '3.7.3S',
  '3.7.2tS',
  '3.7.2S',
  '3.7.1aS',
  '3.7.1S',
  '3.7.0bS',
  '3.7.0S',
  '3.5.8SQ',
  '3.5.7SQ',
  '3.5.6SQ',
  '3.5.5SQ',
  '3.5.4SQ',
  '3.5.3SQ',
  '3.5.2SQ',
  '3.5.1SQ',
  '3.5.0SQ',
  '3.4.1SQ',
  '3.4.0SQ',
  '3.3.1SQ',
  '3.3.0SQ',
  '3.2.9SG',
  '3.2.8SG',
  '3.2.7SG',
  '3.2.6SG',
  '3.2.5SG',
  '3.2.4SG',
  '3.2.3SG',
  '3.2.2SG',
  '3.2.1SG',
  '3.2.11SG',
  '3.2.10SG',
  '3.2.0SG',
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.12.2a',
  '16.12.2',
  '16.12.1y',
  '16.12.1w',
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq28110',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
