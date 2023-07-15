#TRUSTED a7ef56ea4f42c5d75dbbda2f967fbdc2f2287cf2a89ecfc8dc882b486e71d65d6501d2aa4814cd7c2ac929f2c9b0fca9fa4060f726c9da5b3059abc3031104f282022413ef0e9bfc03ba8ee8d0259a766f61872257fa3c4715824d31a4b67b37c7afad4e030204e907363ee2712a0df8eeb62f80a311e09fa410efbcfd537f6ebe8710fd7ebfc5faa940c97c8801212811591f3a733b1fe27e9857c1102b5de3e27833b5493f97e872c526da316f462f87ea1f51e46c01cbec01224f494343203bb8e1e20a2968b42e5c2b1ee7a11208262fa46444ebfb2fe8eac028ae478456c4e5a34606a3fa162b4f5c287e4d3e648fe24f7d6654386c85bf545ba27a637ce5418a749a5beac111c54b165497506c757b45e8a5d2db0296f2780fa5246cd943a9b16b052f9d1c60e6473d077a8b5faea9180dac1b5d8646828ae2e519dfe28e160b3dbad7dd9cad3d2a23779ec6afbb7f7142f0662217d9427d31193d56bc67427a52d6702160b14e9d4ab1a4d66aeb5bb8e0200eef8ae65fd34fb32edeb78b8df0b0643ecd99ed201029d95bcd0c3953c697730f61b40bce6eb27314d3b6259f342d5259c04591b8b366ef2427bdb8df0687700a6df610b487216445cc9a6e5df120cdf1f0c0b762fb057ed8fb4b0ebe0499c5f15a87813d7c4bac48c3101e2639b61053393dbc638a091fcae9145fd19abac7eaaa5112830c0678dfa9c8
#TRUST-RSA-SHA256 027a1a3e65094196e96c0de1321b9d50adbfc633a5010e5a11cf4dcbc528fae99b35331cc2f7c7418cf7e53ebbcafc121a0da42eb380d97432a502f3cf8c9a6960b3351e973736cd960844c6282065c87e8999f4609a29e7ca8c22ec5c7661a17c619fd4c94d3ba879e0c233e54417e189d2a93559ee68342925dd6484509b6d5270f8285685ca09ea46c169c4b598554d7adea144cb9d6c7af3e486a3e41661907e68f14b0658d03789fd69a70c8e207c930395e529ad1b9d6e061dedf1cca5c22bbfe5241e4fe6624c9da8595b0a387fd4a120575732ce07c0e61e375809fe0da93b1403c88b5c57f6f2cc7d2a5ae3d08a13174232f81e116fc35018fa0b7b1a70189bf2fb0e7b25709b32d30bf717b3252470ef5fbc28378fa1f9a17caa74af32d18d3393d5a8e071788281ee70a74cea9f2acfc27548379b36339d3e71451f7bc2dc1532318fdff8d0fe75c4618e14038a5e1cf511d562956e007ed73b6b09de9241ad59b7d5ac5c5c3b0751bff481724d2a8c4c150b37618fbb89be211e27b777201d507757f5703fd090aef704a8778f15e4172323c65881839f262778286186e3958a1aa437bcc6263eeace51bdaed5aafda8352a2a62a61f13244fada9ad312733a8ec52c5c11a35d0df82d5df0c37303805f692423fd2483fdf0d1fad9f4286d95eaf0ef6053d86bb6c47e2692ece3c052f0f2e40890773f57dcd4b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168368);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-20694");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz55292");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-rpki-dos-2EgCNeKE");

  script_name(english:"Cisco IOS XE Software Border Gateway Protocol Resource Public Key Infrastructure DoS (cisco-sa-iosxe-rpki-dos-2EgCNeKE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a denial of service (DoS) vulnerability 
that exists in its implementation of the Public Key Infrastructure (RPKI) feature due to the incorrect handling of a 
specific RPKI to Router (RTR) Protocol packet header. An unauthenticated remote attacker can exploit this issue via 
network to cause the Border Gateway Protocol (BGP) process to crash and restart constantly, potentially making BGP 
routing unstable.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-rpki-dos-2EgCNeKE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3931bd3d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74561");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz55292");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz55292");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20694");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(617);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '3.7.0S',
  '3.7.0bS',
  '3.7.0xaS',
  '3.7.0xbS',
  '3.7.1S',
  '3.7.1aS',
  '3.7.2S',
  '3.7.2tS', 
  '3.7.3S',
  '3.7.4S',
  '3.7.4aS',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.0aS',
  '3.9.0xaS',
  '3.9.1S',
  '3.9.1aS',
  '3.9.2S',
  '3.10.0S',
  '3.10.1S',
  '3.10.1xbS',
  '3.10.1xcS',
  '3.10.2S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.11.5E',
  '3.12.0S',
  '3.12.0aS',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.0aS',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7S',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
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
  '3.16.10bS',
  '3.16.10cS',
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
  '3.18.9SP',
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
  '17.6.1w'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['rpki_enabled'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'cmds'    , make_list('show bgp rpki servers'),
  'bug_id'  , 'CSCvz55292',
  'fix'     , 'See vendor advisory'
); 

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
