#TRUSTED a8d815b8294715b88429642d32950d6191a542cefc694116dc2289920e26ea12660889a0618d7d1f450fcf13d2744b338b836898b9f2c6ea9dc50b3ea2917926b57395202027ec38d71fccf6c2b6cffc1fe73bad503bc53d2387a3627cabd4f0749e47737d2931130b797dd3fc3672d732e15df6e8ecfb18da24f3bbcfa35ab987dc17e6c61e8f08a82eb02ae2c4009314e7f282a96a5ab74dee2faf56b2ac5cd186b3985b43e53b31fed31ec82d6bc43ea45e5780405c3fb88750153937000b75007a4550d1d72430b39af8919e23db7594492bbca76f5afb3cbb37c499fc2885896d242dea662179eefd165a00a4ff349e316e46290854af8d3659f8be250def489f0c2d9c2436065d045bd40f6521456aee55fd2dfe5cd098abe7b170c78529e860a142343d64b3e20745d33e918799c239feb7920f3c290136e4faa53bff8d325d0bf7e2ac4a9d791fbea866973d11cec09becc07dfc19d009214e01588b7c8d408d592c320e9e41fee35984ebf46e846e1190d05514a1b22f44971d45418ed51c44947e6db3837dd42eb44b131167cf3ef8684a638a1e1d276bf14f04df69dde792e8ba7336a3b060d02c4e2c6165140c181dd637c65fa7e619304396b1735e813bf886bd95c471290dc0de09b6e7ea86a0f2813630ef4a55fd60ce40017ff022e5a7ea2d2f32ecff8a3be4b79a859902dbcb2a74179f3339ffb7c6d539
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130272);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-12678");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp45882");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-ftd-sip-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Adaptive Security Appliance Software SIP Inspection DoS (cisco-sa-20191002-asa-ftd-sip-dos)");
  script_summary(english:"Checks the version of Adaptive Security Appliance Software.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the Session Initiation Protocol (SIP) inspection module of Cisco
Adaptive Security Appliance (ASA) due to improper parsing of SIP messages. An unauthenticated, remote attacker can
exploit this issue by sending a malicious SIP packet to an affected device which triggers an integer underflow that
causes the software to try to read unmapped memory, resulting in a crash.

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
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.4.4.37'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6.4.34'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.7'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.56'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.27'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.2.1'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp45882',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
