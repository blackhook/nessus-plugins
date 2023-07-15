#TRUSTED a94caada74715aad8bfa1e9e019e500a9774caff3139d940c23ed0119fc3c18bf00f4b22b52c64cb6a39e7b877a246bc60626b764fb71c8d49b6bd8f73323af648f73fb88302406e0ba891a1605de77bef3156694f4591b56132743851c4021ae25d117f1bdd0b08ff665d120d72650de88657b1c0999a33f6d99154669b6bf545e6c03cbfc612206075b98a5be29179811423e538c5e897e9eee59b1df1bfd6570fb74fc140c39b0e32ec269f3d6af1b693aacd2c0e63313c7b3cc2ef83e91dba59c591b2d3af021ca7b355a5b29e854475eec2fb48b92e800046b938cabb646c9d14de3cdfca8549cf46bd01b9342d8f7b4cc2c3307c68466f15735b45fb7f7c4841ffa4c8b4efab3b8d8b51e38d5a33ea4a64378d7252f5c927ba1bca558f2d54519c0324b1778eb52db0d662c3624ae504082de96c976502590af839c483f3ae667a1a3d72b2665732f32f04fcc6e80fc428d08b166fcbf15f69fc2dcd9463274c95ea6824dbb2f7195b386c02cc7c8db86ddd1662a032c022dcff8d9977a3866e2d3aac30b2e5f41a4a866fa68d8831e4c56b07582dd321bd36b2ee1286794a765bfc955f8c61e0a905cb2bbec034c896148efedee381c4440877b443265f99fb85ab42f5f929042db11087c31e725b83732c6a23f0a7cf2b698c54157ba5de08c61ba85fcbea9cb0016e9a763f9861128a5f04aed0b87db387698ed5d0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135198);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/14");

  script_cve_id("CVE-2020-0311");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve04859");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-fabric-services-dos");
  script_xref(name:"IAVA", value:"2020-A-0127");

  script_name(english:"Cisco FXOS Software Cisco Fabric Services Denial of Service Vulnerability (cisco-sa-20180620-nx-os-fabric-services-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a denial of service vulnerability in Cisco
Fabric Services due to insufficient validation of packet data. An unauthenticated, remote attacker can exploit this
issue, via a maliciously crafted Cisco Fabric Services packet, to cause the process to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-fabric-services-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a5a1307");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve04859");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCve04859.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0311");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(product_info['model'] !~ "^(41|93)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '1.1',  'fix_ver': '1.1.4.179'},
  {'min_ver' : '2.0',  'fix_ver': '2.0.1.153'},
  {'min_ver' : '2.1.1',  'fix_ver': '2.1.1.86'},
  {'min_ver' : '2.2.1',  'fix_ver': '2.2.1.70'},
  {'min_ver' : '2.2.2',  'fix_ver': '2.2.2.17'}
];

workarounds = make_list(CISCO_WORKAROUNDS['cfs_enabled']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCve04859'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
