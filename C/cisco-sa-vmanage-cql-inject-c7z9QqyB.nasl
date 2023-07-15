#TRUSTED 7b812cd422ee0db0c23556c17a1bb3d5df96953559ab4c4370ae5df786be4bac6b0f74ff5af03b05d7338a6004134e6813e76fa3cca8b5fb18709639831c350dd7fda57e7106c5a5dd4be43ed1d432a1eef44b913afc2fea9a9533866b654618b664cd0fd62682ba75a1c9dc2435766b24c36be5ef320fc95bc5ee7032f6679ba99eb0244d0f1ed4d25e0c94a5d4b05c07787db96ae1e25bb5d3f425cbed354cd13a1a6b6fd73a95a0bd9f1005bf0749983b0a251ddb59a3a4562f3e0497693b5fcf969aeb31d012cbefe1e0252ec189838d9d5865d46622e1b95f07841afed10f8b4b38c13a6db35aed1cb0b410e7f0a983ba1b03a1108d1ba995447a7ae50187d1e55c987d26c7ec213da5ed6fd4b14ecda5f6d9a9a0d7f5960882caf3f8eabb0b6f17cfa53db54e6e7a0e5b23e032d2359270ea83459265c7ec52c14d0813583ec10f67d2c7eca8de2fce16bbce0a32494ad1ee016c1c1581a1f8bd284364715b55c282a3321085f0001e7f3d1bfa85a93dd05af6c3a6bcd77aa7d66b7c29b53787e2b7ad07a366a57691044879887848a27a62467dc6206a1b1318002a7f6e5ffc067eae9e5d05d962b588e9404c9c40465f22ff335a9896cea3e3845ffe1f5b045796de9ebfb59428acffe1e6f6fdc97f6c9ae70043f92ec56e5c9f9616246c981ab3c2cd254cef2707ffd4bcc16aaf8f834c2eac88c05fd0093549c624
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148957);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1481");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw93066");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-cql-inject-c7z9QqyB");
  script_xref(name:"IAVA", value:"2021-A-0188-S");

  script_name(english:"Cisco SD-WAN vManage Cypher Query Language Injection (cisco-sa-vmanage-cql-inject-c7z9QqyB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-cql-inject-c7z9QqyB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6fc531a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw93066");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw93066");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(943);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.5.1' }
];

 
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw93066',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
