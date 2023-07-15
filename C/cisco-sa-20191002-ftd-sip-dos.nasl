#TRUSTED 09aa7490dd2d9695ab53ede0dffc67e4d7473ded06668fa79ff9539a7ad422e3eface519bf3fbeb7fc59396e6131989896a80a64f3a7ac25bf92a7352fe317c2e4c1dee96fcfa2a3c92c8aaff97c2f73fd40c03f21650f3fc3e29cd55208e76f86e8f2a937dc3cd1c5a5b7220c68d556ea75dd15b4a4f0d4e0e329a6b9867adadbdc46d315fd83c80d9a6c1e6c1a689abcc96d27c195a4fc511ebfefc1324f2921456ca764babe1f5bd479ccc26c10d0a3546e00302bf1b084b141fa1f0e54ab367802edd133e94e5e27fff70b87e963f11d9b140cc19a920e15c2442656d708525521e33a173c45e04892905f6bc0e0566548226b730b39730eb481acceafd2e96e65cf420159c68934c0c3136d0f585cc747d42b8f5072b7b0555c268312c1112497b73abccee6691fa47733edc3edb809e37faa12789e55db48dbe2818ea514c85bc02c11f81e1c7f1e2e4b264dc8589bb52756ea3b65a78d0fc031c5382e6b12fec1867b56d3150f75464fb45caf4b4bcd4aa8a5c41da6f2027550bc5e551a4bd9790d4180105e1354b79f0b876d3a46fab7a0d64f76c18382ad4e22e03b3db110bc5ddd80aafaea3af1bb447837ab33b425a35653bcf909a747abc56ef3097d047439e7e3aca91c30b639c776ae7061cc7229f9d296cf0f7b9585b5fc94f43cb027ce200f4108945745a37f710263c0c444f1ecb55a578cee55e7c1b406
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131183);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-12678");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp45882");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-ftd-sip-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Firepower Threat Defense Software SIP Inspection DoS (cisco-sa-20191002-asa-ftd-sip-dos)");
  script_summary(english:"Checks the Cisco Firepower Threat Defense Software.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the Session Initiation Protocol (SIP) inspection module of Cisco
Firepower Threat Defense (FTD) due to improper parsing of SIP messages. An unauthenticated, remote attacker can exploit
this issue by sending a malicious SIP packet to an affected device which triggers an integer underflow that causes the
software to try to read unmapped memory, resulting in a crash.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-ftd-sip-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbd25b57");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp45882");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp45882");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12678");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '6.2.3.15'},
  {'min_ver' : '6.3.0',  'fix_ver': '6.3.0.4'},
  {'min_ver' : '6.4.0',  'fix_ver': '6.4.0.4'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp45882'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
