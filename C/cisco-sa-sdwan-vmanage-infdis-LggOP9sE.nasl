#TRUSTED ad662dc0b3c982037c235315843984d1b6aae573bc673d54f9515bb6917a6a11d9fccab8b5f84425462892ea7b8c5ad0b07d43e68e21ddd700b235b6f59c843b55aec68f85fdfe0581e2000964547d41076435445511798d384a6fcbc1a2baa1afa7c9914924449dbab9f3f9004996cb8eddf16aafd6f9c115fe2fbe9677cfb8cc5905d4fea30102a18f2e8271d25e59d4c3313c49d8e118c0b17372080f38759621e4e0a77a59fe4795236c84cb3a5c42a4a41ef8b1e269a3e0a2119b607e74992ed4c16132fd7ca2984812d39c1af8c01bad3afef0b5a12c8f17d704e96aa1535af718e50dcc95e9cdb3ec337f434a064488985a4805cb6ebded0cb6aa4ade51475f95b5485410c8861371a15f21b195c06cf1f252fc1bfea34743d5e31f94ce9e1eff132ad38698c4f2c55f8be05d717441a27b1b2d0f57f77b9e812351575f6f619bd36e7a7956759b79e59bed54e15a83ebc0ce259e12acd19b5ddf293e3754f6d6dfaf627ab31875d042b86b1bdfd92a35f6974df1d33d3084c6f265f6a55658d542d3b2888246ca5097b0a325ea56a47e29026bcdcc5d57473e1496dd2ee4139c7e8978c9a9c8e9335ba6c8dc1c40c0386ad4f56ccac493f9ee6e334aa5a6b19a05b36af93dbb05a5656ab306738f69bc557fac9e2640188a5fbd04d1762582556e4c9ea303bc2742fba9b6b61577fc1686971ea95859c84f925e86b3
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151916);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-34700");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53695");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vmanage-infdis-LggOP9sE");
  script_xref(name:"IAVA", value:"2021-A-0351-S");

  script_name(english:"Cisco SD-WAN vManage Software Information Disclosure (cisco-sa-sdwan-vmanage-infdis-LggOP9sE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vmanage-infdis-LggOP9sE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fc87199");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53695");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw53695");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(522);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.4.2' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw53695',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
