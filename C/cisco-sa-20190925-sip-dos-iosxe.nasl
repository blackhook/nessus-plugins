#TRUSTED 60b626dc715b498ad1b777f470c098b260b9665cbb0e78af59a316e2f7627bb5996f9a8d881df6342f804a88cd43dd21f3ceb1dc8b94413178bf1007a0cface963a2e168c0a844cf1a9e7caaa9c2e84f2017ed5531d1d3112755ecd9478b4bc1b5bc8430737994743af544a79ea756939b0a2f96269cd6d9a53e78289dd76accf65a4e5f00b27dabdefad3179a5453b8988bfe5e3f33769f72539416ec7a159083fd210bda966d85851a7106e2964eb9d45f860a8c8c32bca0cd0ecfe0731d6a1ee0fb18da6c9b68e8f3291ace0942fa7e760a8d47a233672860af30814843cecfe17fe9ebfe3f7b8ad68587d86a18e0c0d75e428e0a25c4cbd5dd72c2cbf5e83bf768430d7774889a0dafbeeaa18ddaaa64c264e6d83f28b92e5aa39c9544198804d9d7cd69cffd4231f786668f81db454ed2d8113b1e67d4572808ee01f268889fa51a25090f89d03d603935f433ee600c8c972585a1911bc5a06b6a26a21ac859d61711c2238bd6058de9eea02588443a8f81ec2a12ddd6f91e3ce3ae9d9732b4cfc5596a7ea9cc3a4f2ca355b8b791ba443778e5fefbf7d2e78081e039e59767190274c750b2ca55ceae8a18a69ead1063d5d2ec8927e6e4472e9c6800388d8bc55cc9327651675d00f0173ff3a699b02aab6a7a8db159a30235663e35cbc54f972b65c463c250f9e081832c99e2bba9719b6200e2948fa1d94ae492d180
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129695);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2019-12654");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn00218");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-sip-dos");
  script_xref(name:"IAVA", value:"2019-A-0354-S");

  script_name(english:"Cisco IOS XE Denial of Service Vulnerability (cisco-sa-20190925-sip-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the Session 
  Initiation Protocol (SIP) component of Cisco IOS XE due to insufficient checks on an internal data structure which 
  is populated with user submitted data. An unauthenticated, remote attacker can exploit this issue to force a restart
  of the system.");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn00218
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e59804f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sip-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0995245");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)CSCvn00218.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/08");

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

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
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
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
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
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
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
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
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
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
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
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '3.2.0JA',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
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
  '3.18.5SP',
  '3.18.6SP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.5a',
  '16.6.5b',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.2a',
  '16.9.2s',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.2',
  '16.10.1f',
  '16.10.1g'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_processes']);
workaround_params = {'pat':'CCSIP_SPI_CONTRO'};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn00218',
  'cmds'     , make_list('show processes')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
