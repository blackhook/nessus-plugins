#TRUSTED 18a9f3423cd33171616009115fb434660d33f1a30dab389f2e34bc55272434902a523a5aa71608fe183116eb03c86c08e55a932dcdfbbb1fc9b4b1433304f5b0604d60bd587d43e8bcab9659ccc35185b74299bf88449d0ee3413c6f8da16200feb4e0f80c7ef93d8473abda05992b7289ffd99399bd654bce867dde69b3e2f4fe2785ab1325b6c920b54c297b3f52aa8f0d3835f1c76e4c28d6c8811c4c280282c72ac63c5fb1a8c9df93a26311f90582ef097ee5673c27d0ba58485356c96da4a6d88c5135f76f4b7affa81b6748679e9e76359396be4f4fe4bfab698f13eda4707bd0998b3af82a904df1a732701db488c3b45bdd8b8e53ed41cca7b9c6366befff20c9b6480d4504de5207e2ee039e1ea5a3baec508268226765f06cc6c8a0154894e4775f2cf1788f576a4a121c641b34cff56b149ab168fcd5b9f7903f76eeee8617c04a021a4fa70c8bc57254fd70c0c874128899d4f8f1259a413a0c21b900df0fc335e4ca2fb2271abd314938e53e4e1a2a021b01cec9ac3acbff8ba047637cac293b3046b3fd36aa14db59f5f88ea026d6fff389c5ffa5e9cb7adb32856b5d70d9a43cd1bea09a24159c544ade08a9bacea657845e7e0befb6b085830f5d0d576a522b8d673d48e6bbde5d10f8427503325dfaf7afbd2064e87159ead91bf852211c5d0e03a8637f0f5266b9de64110059e217796ef40e3da66c02
#TRUST-RSA-SHA256 3d82d65378c2774a9d8bfebdf2d00da1d5e5bb43e0101f62e60849bc822b536ebb9a74e18476e2cc0e4a44516f1beb2228e09f36c8c97d1c250873ee37c6ef2d4b84f1f8609955aa6986a8fea00997f7119d4b7c3282eb13afa2bfcf694e32f36cb18aa4eb0d17f51eeb7cdb43109f962a5f288ea17745402e6f33261617f7d1b5502576b261a1de04e9a391cd7e5ac48528832abfa30d0802f5cf2a8b1ad2aa6778092be84a568ada47e9a9357cb513edb31053fc34399e8f30da74b18b0f4711a1d5c13a58814a0aa80bb2200e0feae8b67c722938b7b5402472b443ee1e6646f07cc9928bd9b894acb76ade7fe70eecdadd5a911ba171255f33c2f821615be7ffa33ecd10cb4bf735b40e79445939834c17cc7f3c81b1179edb518f1c48d4738b6e78aa1c7f5375016b7e7028fbe96d4d9f84476a6466a35fb4b5d2364f390edcba1c24169a8e1d4ebbcdce2028b15bae51c49531cee33c74bf31445184d4b51b258f8cffd15d6fea51e6a6224034c3cbb04cd25fd673f8fe8f9ff3d837f839f886521be59366cf5aecf079d1225b680a2687a6bd67516487733211cc000eb551473c710bb0505f1ed6e8cac128802b00966d9df6198d1f85907df0ce25de74f56f51648d0b465162ef33330eb2a1c15e3c765b3669bdf4bc764001f062fa9af67583565dd6a14345a07e33a10f42aac810be3bbb66af97d6acf3768f61c1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(127893);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2018-15399");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh73829");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-asa-syslog-dos");
  script_xref(name:"IAVA", value:"2019-A-0271-S");

  script_name(english:"Cisco Adaptive Security Appliance Software DoS (cisco-sa-20181003-asa-syslog-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the TCP syslog module of Cisco Adaptive Security Appliance (ASA) Software and
allows an unauthenticated, remote attacker to exhaust the 1550-byte buffers on an affected device, resulting in a denial
of service (DoS) condition. The vulnerability is due to a missing boundary check in an internal function. An attacker
can exploit this vulnerability by establishing a man-in-the-middle position between an affected device and its
configured TCP syslog server and then maliciously modifying the TCP header in segments that are sent from the syslog
server to the affected device. A successful exploit could allow the attacker to exhaust buffer on the affected device
and cause all TCP-based features to stop functioning, resulting in a DoS condition. The affected TCP-based features
include AnyConnect SSL VPN, clientless SSL VPN, and management connections such as Secure Shell (SSH), Telnet, and
HTTPS.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-asa-syslog-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fd359b3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh73829");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh73829");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15399");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(332);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

if (product_info['model'] !~ '^55(06|08|16)-X')
  audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

vuln_ranges = [
  {'min_ver' : '9.6',  'fix_ver' : '9.6(4.8)'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8(3)'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9(2.5)'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10(1)'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh73829'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
