#TRUSTED 90b4efa1e40f6d935e6a00bd18ca1e621a24b4f0006b0f1ad0950fea47a52c5da73e571e35c2b266b0e60d8f776fa462652eb13700e749ff16a513278f31ba1966e96fee800928fedc3d38d7945b86ec531a87eb864f6f2b9bc620d56b3f470be03cb5494130d11c7ae2bec29cbed5eb78a69cdd6c5d6804bf826f9ae1942777940f7cc703e7c0f70f504132cce1c2dba1669aa9eee934635eff515cd8e8a68714abf93d3e044fab94433c1ede5d8958e2717dbab8fd207c8fb2f97b2c9a4631061da18e51ff71bcdfe690c5b8416c36dea73cce2e831986b1be38e9524eba5db97da1c3c958e3a58ab7585efb47a38322642b516de6449b8cb75ace9c1858cee6bf010293a11dd9163b2ff0bd0c9e1aa2f9f04c377cc0e1e8f6b38a4b096e635cb4522919b821ac4794d0067462c1d51d7ba58f95148222666b837473628023dc80935304706b8adeabf85feda39e66c6ecdc8fd87f21e0f6603402c2a60173942ec5214d54fa25090274c3300ff6ee26a0577acc4dc5fdcad52fded537b3633d7e66fd16bbdd2361ebd79f42cc2c82aa46b0e695a8238f209f2a4bd10eab7ef35f0781dd3345a0046639ba5d9eb04ec4d08e3c7a36e34128e215556c71d48f4e4e988de140e1a46e56f2345fabeadb92c5429905e25577bbb32d36ab9f811087baa0246031ab3df071e9f7dabd4a8e0f956509be54d83311ac7f3358764ca1
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155370);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-34792");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx79526");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-dos-Unk689XY");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Resource Exhaustion DoS (cisco-sa-asa-ftd-dos-Unk689XY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a denial of service (DoS) vulnerability in
memory management due to improper resource management when connection rates are high. An unauthenticated, remote
attacker can exploit this, by opening a significant number of connections, in order to cause a denial of service (DoS)
condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-dos-Unk689XY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01162636");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx79526");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx79526");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34792");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.14', 'fix_ver': '9.14.3.9'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.17'},
  {'min_ver': '9.16', 'fix_ver': '9.16.2.3'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx79526',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
