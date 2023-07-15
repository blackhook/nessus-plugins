#TRUSTED 56b0fa18b98adb87620bf812a46217644e9d73e82ee6c6aa4dab26dcc2417f92115cb9a1320c76f9831064ebdb9b9ac4786386f796f13fdaab1492a292a8bb2e19bd61be67d45ad9a680e015136bb933eb7120c3b2c2573014fbce381ed6020da78c221daec1b01a7389d72cbef65d9de03abd18d4e53e45d2a93c12c17ae0d8f23d081866c01e97d73197a4a01648b220f4d89872d892e4f83b2ddefd68526e15279f52bd555d6866e6fb27a913b0ce6978ca0461e5ab0ed707fd678009562c2c723ef10c45f0ccde862533c8399946d2f8b827cd4fa14edc01fd73cbacf4ea7f98e5346e543e6879bca10bd115a8a27eac776079e1d199c65e430948adb3df70903443bc36bed46247523b732ced65d5f7f0285ae9f8b743079757ab64a8c97594b99ad74e27aac0808d882592e9cbf19b43819e5d9a9376fc6470c8acb41c5d136cfe95bd6a0d05e71a150b0241faf64b2191798b9d82fcb70174b7d73d8198b449950c9f26e47b9696ad20757c20f6b0198d7c3bb0f6ff81b5bca22084cb2ab1a6948e90295f4835512bd8b039be4f32fb97128a355f1b0d52e11fb4a4746954710ad7e8e2a45cb48a0238a4d38128d5f25e06ffffc2bd2a42ffa6a69065aa82401bd3928018dc09d88bb0b1674eec0052051002690446651144ea471d30005674d945cfe4f2c530a4ac1f7ac7ad41e05c23eab491b87ddbacc48af0c3ae
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123789);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg39082");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-tcp");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software TCP Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the TCP socket code of Cisco IOS and IOS
    XE Software could allow an unauthenticated, remote attacker
    to cause an affected device to reload. The vulnerability is
    due to a state condition between the socket state and the
    transmission control block (TCB) state. While this
    vulnerability potentially affects all TCP applications, the
    only affected application observed so far is the HTTP server.
    An attacker could exploit this vulnerability by sending
    specific HTTP requests at a sustained rate to a reachable IP
    address of the affected software. A successful exploit could
    allow the attacker to cause the affected device to reload,
    resulting in a denial of service (DoS) condition on an
    affected device. (CVE-2018-0282)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-tcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9a0ef5b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg39082");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg39082");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(371);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

version_list=make_list(
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.6.0E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.1E',
  '3.6.2E',
  '3.6.2aE',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.6E',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.8.0E',
  '3.8.0S',
  '3.8.1E',
  '3.8.1S',
  '3.8.2E',
  '3.8.2S',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.9.0E',
  '3.9.0S',
  '3.9.0aS',
  '3.9.1E',
  '3.9.1S',
  '3.9.1aS',
  '3.9.2E',
  '3.9.2S',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0S',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1S',
  '3.10.1aE',
  '3.10.1sE',
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
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S ',
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
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.9.1b',
  '16.9.1c',
  '16.9.1s'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg39082',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
