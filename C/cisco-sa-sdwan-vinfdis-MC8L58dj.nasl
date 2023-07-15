#TRUSTED 31a19ac7433bfc8596470895a3f1ed31166c9d918e0be2fa22f4d7e35ede6293870b09908e494811b7b70b7f62d52725bb014bf4adf2f14701ba71e2f87f5edb3619dc5a5625f761c11ca85a47048604daf7c186e9bcb2a91babda8344127faef380bad918f0834b2538a7b0d869ddfd9967a1799c8b6e867d16140e1e11a985c5fe7a7fe5bd9b13b7440d35ddb43051b99ab0a702d6c39d3006d91472bbfa2cfab9efef3d1f88e4ff514eb4da90772da509b6294913d203c93b967b709722bc5172e2143b77f54f942fe9bf7542b838a676757265c646b653607604cbb2182f24c4b751383bbf7b01ccac82ea6a65ce9165be10b7bff7ceb3aa274948a2c0916ea779a9eb4d6de03f4446eba52c65b6806ab83fe86ea8b9a1e67b1f3aaf4d1970e11d288b22e29b1b49f5acef5cf640de0d9d48c67d085ab0b6a70604dca8b76cf211cecb135a75a8d7b3dd1ef9fd3fb196bdc27b249d1b4d9fd96c63830fd1e3c81d219f203533393dfaba6fe3d97b4df8f9e6af9835ce967a86b9c814a0a7e02ed2f925504a0927f6df2d42a0e9d4b11cd2f6ad14c4420b2c2ad548d204ae0311c0ec1cdcffa6fe299dccbc0091191cc689edb544eb52fafcef1de59d2a67ac03244da58d2c33cbb6d0afbeccca2778f72c378d2c2d0b582fb14ffcff8fcad27132b58051d12038f9ecf77d0d815880aa74575da37c6414ca021ef4d401e8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145501);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2021-1235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs11276");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vinfdis-MC8L58dj");
  script_xref(name:"IAVA", value:"2021-A-0045");

  script_name(english:"Cisco SD-WAN vManage Information Disclosure (cisco-sa-sdwan-vinfdis-MC8L58dj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by an information disclosure vulnerability due
to insufficient user authorization. An authenticated, local attacker can exploit this, by accessing the vshell of an
affected system, to read database files from the filesystem of the underlying operating system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vinfdis-MC8L58dj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?321da1d6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs11276");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs11276.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(497);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
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

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0',    'fix_ver':'19.2.3' },
  { 'min_ver':'20.1', 'fix_ver':'20.1.1' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.1' },
  { 'min_ver':'20.4', 'fix_ver':'20.4.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs11276',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
