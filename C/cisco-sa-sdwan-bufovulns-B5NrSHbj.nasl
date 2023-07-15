#TRUSTED 05c29c71d7f48480d75add909f5155f57a71acbeae4ca41d042e8d2b4ebc232c7d11fa381d46698c48528f083a7b24f112a07be71a60906afd747b4471e781cbe7cae3704d35af790f10c627a9b9c0cb5a64cd47789b15356a0d7201610825857c7608469376c8886bd13d82cd529d51da1454f09f8aab2ebc159419531b6543eae06338e4f66bffad1ba8acc0f5f73a21915acc8a5c72274421feb571668a163720e9f54882b1c03afb7761d607e2652cca3124a28283e4f6f181ef1457a41806437f94c3f6f6348566b1f59500b723ee0f125abb4510b9b73b6541abb5c86031afc78e0e2595ab6ed80629a557d8d425c3ee842549e57c8da3722328fe6c3eb3b67cca8f695680d76a5691398b1d810c1c8e70facb95e9d373239464c39f6b4fec5624873d79be07b21508abe77a6da1455e390d891aabe29d6aadaa16223d7f638d1e4644ca16f58a0668f460eae586e152315ad818c3f23233f71891ee9f40fa2463204093e291f7e1cd029bf63933a8117310dc962f9abd6e628890dbb4d2798be5922d09e5d0a3dff36300dd844890a5342ed3ff9023ddaae3dde6f2a80a1f89a2ec1e358c7840688b528439b2647fb8fd1acb4cd4cd788655ec7c0b446406267b83e47d9557acc353ea334226bdf82d7b88e636e46ac040670708a32c57df9a8ebbf1ce856ca4cf6cfeb75c9ac23078d8a7dcddf8219e23cc04263f8f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147963);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/24");

  script_cve_id("CVE-2021-1300", "CVE-2021-1301");
  script_xref(name:"IAVA", value:"2021-A-0045");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69895");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11525");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-bufovulns-B5NrSHbj");

  script_name(english:"Cisco SD-WAN Buffer Overflow Vulnerabilities (cisco-sa-sdwan-bufovulns-B5NrSHbj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN products are affected by multiple buffer overflow vulnerabilities
that allow an unauthenticated, remote attacker to execute attacks against an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-bufovulns-B5NrSHbj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f3f0159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69895");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11525");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi69895, CSCvt11525");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "v(bond|edge|manage|smart)")
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list = ['18.4.302', '18.4.303'];

vuln_ranges = [
  { 'min_ver':'0',    'fix_ver':'18.4.5' },
  { 'min_ver':'19.2', 'fix_ver':'19.2.2' },
  { 'min_ver':'19.3', 'fix_ver':'20.1.1' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.1' },
  { 'min_ver':'20.4', 'fix_ver':'20.4.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69895, CSCvt11525',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list
);
