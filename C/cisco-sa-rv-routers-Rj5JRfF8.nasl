#TRUSTED 104835751e497bbff14f048e482e55dfc3a56032ecfaa319ab0839477dc2e1baa2f5b99f7054a4f31ae0ee0b1874eb60404780b356b0b2ad214e8f9bfe34d24cdc6fa6834538263b45080a1b79fbe8fa7d84d32f9fea2a8ac62c3b73426f3c615a4d94528e45eca472338713e47be0d550a5db4b82664c5f697f269e6edc944a5e5582c7761b23b246a501f289833fa9d12ff1e89ff8c581381d6fc294c98655547ad89c1a15c85cbf63a5d8bae360d6eb49a3e57d5b8a47139a7fb7f22f8c682043c0f533bd45001398d48be761aff8cf1c984725cfdc2226164084ecce9348e4e18ea8dd34ea643f1285d21d929d03583c11e03e3c91d42f68cdba687541d415f24f59ade54d765e9640945f391a4d01f07072e36a2b457d51c6e7de16619125cda01f60f0548929b68d9417c6a0d865c270e91b3e0cf16c12e26c859e3bb0d7787759bc8abdc47f9eb77b02558b02a2eb3b40522887cfb3c82ea22389ff55092f675e99ff8b5ff5cac9a379e960dd8c8c0bee76f4cd989e8924c20f423936395241398143c3871d3deb130754c5eb3eaf090f84fce27d514ab00ed6effd69d8fab04cbee4f091aa6bcdb0e451181f59ff1e2d68fbdf76d50875ba654de10a5128adcba131aab1440c0682f5d05d0663b107fa6b399b6e020bf6031ba4efa26b80eacc53a83d94b429a9896ec547c966ec88c4297066a92e98b336fcebb584
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138019);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/23");

  script_cve_id(
    "CVE-2020-3274",
    "CVE-2020-3275",
    "CVE-2020-3276",
    "CVE-2020-3277",
    "CVE-2020-3278",
    "CVE-2020-3279"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26490");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26504");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26669");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26683");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26714");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29372");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29376");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29405");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29407");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29415");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-routers-Rj5JRfF8");
  script_xref(name:"IAVA", value:"2020-A-0274");

  script_name(english:"Cisco Small Business RV Series Routers Command Injection Vulnerabilities (cisco-sa-rv-routers-Rj5JRfF8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities. Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-routers-Rj5JRfF8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?feb06e74");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26490");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26504");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26669");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26676");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26683");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26714");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29372");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29376");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29405");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29407");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29409");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29415");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt26490, CSCvt26504, CSCvt26669, CSCvt26676, CSCvt26683, CSCvt26714, CSCvt29372, CSCvt29376, CSCvt29405, CSCvt29407, CSCvt29409, CSCvt29415");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3274");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

version = get_kb_item_or_exit('Cisco/Small_Business_Router/Version');
device = get_kb_item_or_exit('Cisco/Small_Business_Router/Model');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (
  product_info.model !~ '^RV0(16|42G?|82)($|[^0-9])' && # RV016, RV042 / RV042G, RV082, 
  product_info.model !~ '^RV32[05]($|[^0-9])') # RV320 / RV325
  audit(AUDIT_HOST_NOT, "an affected Cisco Small Business RV Series Router");

# RV016, RV042 / RV042G, RV082 affected version <= 4.2.3.10
models = make_list('RV016', 'RV042', 'RV042G', 'RV082');
vuln_ranges = [
  { 'min_ver' : '0', 'max_ver' : '4.2.3.10', 'fix_ver' : '4.2.3.14' }
];

# RV320, RV325 have different affected version <= 1.5.1.05
if (product_info.model =~ '^RV(32[05])($|[^0-9])')
{
  # clarify the affected models for cleaner reporting
  models = make_list('RV320', 'RV325');
  vuln_ranges = [
    { 'min_ver' : '0', 'max_ver' : '1.5.1.05', 'fix_ver' : '1.5.1.11' }
  ];
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt26490, CSCvt26504, CSCvt26669, CSCvt26676, CSCvt26683, CSCvt26714, CSCvt29372, CSCvt29376
CSCvt29405, CSCvt29407, CSCvt29409, CSCvt29415',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:models
);
