#TRUSTED 48f5cf27d7b96dc4ea7543ac3a5578a9f2a7850b8c06b364c81ef27ad797ecd2e22f095b5fa3582b0b878633f190d6bdece9a0df95ddbd6b19f498a29e367fe4c28007dee3908e2306bcd6e754dc36f9a5371945cf283429b23009553a168f6f953ddc8a444f3676a7b00fbe1a9ffe2cff2cea7fc5c15faf1da552b466797533d2eda8624f164711a58f3fcedbd288bc15ae849ace21a8525b8b0ff84dbb6f5843859aaef120aa25ef14cf5a1629590fcbce88dcbcb0930880950dcc9678eac2fc1a536a3e9ed1f93d98f78a84183045c05f364130915fd0ac565b03a6047e8aac4744047a2e4bbf391963b6ae9b23e20f11219b6fa727f1fe22b325fc4521a0313a143805c635bcc48da040ce974a3ec70d0cb4ae88dd1177736a29d5c037c271a6fd253818b62c32721f7bfaa4cbaad6ef4800aaf3e78e9283c7a128fba15df16fa5549669d07b4dffd83d864c24020cec1388ba35b280d41af4795054c9f566fb99f9a4d1dd7f5542872d565d674b42abc7b8fc7a6fd3a50ddc940fda9357a8762275d05b67d5cda74ce678270779af85a4df58244606527c5f50eedaca3356bd60641d3927dcbd1f14f6653a9f8e3a7cbeef90fd203f09f8ea7b0c57294fcc798cf276973090ebd8406aedf444beca20de348fc90417ac23ef4fca555145117306c93607adcfc5e9e59e9eafe167c5e30db91b2e751d5cf67ba4441ccf7f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146216);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id("CVE-2021-1349");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv42576");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw08529");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-cql-inject-72EhnUc");

  script_name(english:"Cisco SD-WAN vManage Cypher Query Language Injection (cisco-sa-vmanage-cql-inject-72EhnUc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a information disclosure vulnerability due
to insufficient input validation by the web-based management interface. An authenticated, remote attacker can exploit
this, via crafted HTTP requests, to obtain sensitive information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-cql-inject-72EhnUc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ce56adb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv42576");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw08529");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv42576, CSCvw08529");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1349");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(943);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
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

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0',  'fix_ver':'20.3.2' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv42576, CSCvw08529',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
