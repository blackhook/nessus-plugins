#TRUSTED 3af845c7e90113a8341de56e212d7a3de2703e3dde389ce660be45eb760d4ee88bd5e6b2a03ba342db0f3727bcf4711885b8e7087efea3fafd44707973a6bcd515e1694724e8cbf1e6a7988410f11863c356e45497aef35970816066936d0c8e70e5bd872ea0c8d0d183ee7add0f48866f127cfaf793f5b03d28bc11a945dea3259f989418635033026524e55209363481457ffa6bec86152c2ef4c60bb3cd22b7b80b29cdb385d2aebb02c309a9c36f32f7136621a55a3e26dbdea97781c74b6fbf2e2b59c3e21e8e118e5d8ee6a4c021dbc0c9b3446f1c44c52a7dea798e13c28bde67d4ef5439b78d214091c7b87ee4f423a51ddd9860626377b2dbc219f67ad1c970f266c36b3d8fbfb0808fcb2d0fed3e566ec90d672f0746df650bd7cd7ec8c24a2c8ad03246cc3ac37657d785540d049907bf99d984bec98ccdfd6908affa429b4b07e9609dc239138d58b1e290e9790a013a8a7b61c831b0e85418149b10aae9958a017f4f4e99c96278be993aad2dc80126fde038e2ad611f97e53e9796629f1bf5f1df88a8923ce878bc207cfc8fcf3d6e8eecf8f802a4d51ca378dd61b485f772231b9244df94be42ea43d10aded848e5f26daad8ac84de8b8eef11c73b9aebf6a1cdabeb36fcf87752633d98f7ab419981623f088dbeacbcd921ae8d0666fc01b41264a1b72713ef6728d5c20b0f59009bc073ac1d63204a6895
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150141);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/30");

  script_cve_id("CVE-2021-1528");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx49259");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-fuErCWwF");
  script_xref(name:"IAVA", value:"2021-A-0261-S");

  script_name(english:"Cisco SD-WAN Software Privilege Escalation (cisco-sa-sd-wan-fuErCWwF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-fuErCWwF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c64e7897");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx49259");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx49259");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1528");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
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

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.2' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx49259',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
