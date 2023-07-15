#TRUSTED 40eb27c32708950aad7d1b86b3c371dc526063550698acaac333c0adc4f3cef7b2c50b42e34c4994d5f378bf648e52466832e4f06b91994163323f220009281dc728d7a1ef0c1dd0f416327600a9b4a040ea68d110bacdb8c175b3c420e1a577834ef8ba001542187180e8e237a9199421ff9fc8fd1624b57d8aa191d3000609a90ef4ccf1f99ba0bcbbc57738a60c727790aa2909788b22639b640969b27eb1d2f9b205d4a0429b99e416c263a3799a4a32381946841ae1632ba77e77043d473461fb82952b7bd039940eedd0e7bc09d59f7b71c402994b299b9e6dda075a2f3de7113de11d0e9c7512a336c173d72f65e4da147aee797ba32d5dbb1e9f7672426928d9b355b2a22da1185d6d5e3bc7b42871bc774ba7949f6b3596e5d57521d26d80fc8834846b40411dac4da3336823fcf2c68794bcbd5f2cd18fc6ffe65aecc0c67467c858a18378c25dd1a28b55abc92ffcbfe81ae13fe985bf865f9891f6210ca0e3a93cf51a8470adbe3de2f3d756399222dfa72dbbfde593a7b09b5d18814b758b40eaa6dbbf3bbc4860a1c89518513068f5c04e72eebba06733a288d63f822ddef588a9a2469bcc43501c1e66a280ea03288a8e33c3871b49ec10cbb5138e976ce4a2ba3d3ac94eab3baafc0826029f1945c0384a0b117bff7ba2aeec72418ba9c75913481b5ba7987278033ef0e12099c4bd21747e89e71d6f6771
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142373);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/05");

  script_cve_id("CVE-2020-3381");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt72764");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmdirtrav-eFdAxsJg");

  script_name(english:"Cisco SD-WAN vManage Software Directory Traversal (cisco-sa-vmdirtrav-eFdAxsJg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a directory traversal vulnerability due to
a lack of proper validation of files uploaded to the device. An authenticated, remote attacker can exploit this, by
uploading a crafted file, to obtain read and write access to sensitive files. Please see the included Cisco BIDs and
Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmdirtrav-eFdAxsJg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75186a11");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt72764");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt72764.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3381");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0', 'fix_ver':'19.2.3' },
  { 'min_ver':'19.3', 'fix_ver':'20.2' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt72764',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
