#TRUSTED 63e1040b288114715f4c334e598cd06f0af00ecbdae5cf48723367418a504da2a26b0a32cbcc0904f9a21fde08119465aa6c903576ba99db810ff831416d7f42f93963d49f3ce5fde182a099933075e4bc42097e1d61cc1332429b3b6cb2a84e90524794275c8972ead310a9d4519d108efe0b11a202785b3f3deafd09c191ee3fdcf29b041afff2b6874b7fc0740b64bcbb9b9be9d0f3d354a0e62a50179fdc11467b6f2ce5851fd721b5d88e619bdcc7b8bb11a776363b5c36791fc17db765a3c7ca55cac4e04d6790f1f218e4790a947d2fa3484c9a8b8be1612e28cf03d3da748c28aa7311b03e84c0104adf1cb454576bd88981864da2de8262736df655235b127a6b3db067575fda30bb3415aa350930a277de4c3f227d1054986e91bc13cb62240ce5f56477444fb2723359f1d2a33308b5822b292af08f89a2fcf36b05ffaceedc6b30177d42d3e0a68eeafa647a986f8220fab5ca48257d966938f0eafeaa6f7a31307498c39458b2bbdc5aad300f89f7a85d618a6c65943ee28e997ed4095c7490c16207c68203a465bb8e0424d260b1332fbb9e8c85c94b56c09c4331805e1ea52cfead30529aa46a9974845d2c30ac6effb8ea6ff328ad01a2b3a6a36d9a8ad33fde5803d5b4ef5392d97f1569beae64e1a3fe814777650ffe95bd12ada1d3dbeaf13a6d65d5e0cfbc1fbfa6247a664ddb9c0e11c147aa16f9db
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135674);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_cve_id("CVE-2019-1966");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm77243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm80093");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-ucs-privescalation");

  script_name(english:"Cisco Unified Computing System Fabric Interconnect Root Privilege Escalation (cisco-sa-20190828-ucs-privescalation)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software on Cisco Unified Computing System Fabric Interconnects is
affected by a vulnerability in a specific CLI command within the local management (local-mgmt) context due to extraneous
subcommand options. An authenticated, local attacker can exploit this, by authenticating to an affected device, entering
the local-mgmt context, and issuing a specific CLI command and submitting user input, in order to gain elevated
privileges as the root user on an affected device. The attacker would need to have valid user credentials for the
device.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-ucs-privescalation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76654610");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm77243");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm80093");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvm77243 and CSCvm80093.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1966");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('UCS' >!< product_info.device || product_info.model !~ '^6[234][0-9]{2}')
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0',      'fix_ver' : '3.2(3l)'},
  {'min_ver' : '4.0',    'fix_ver' : '4.0(2a)'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvm77243, CSCvm80093'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
