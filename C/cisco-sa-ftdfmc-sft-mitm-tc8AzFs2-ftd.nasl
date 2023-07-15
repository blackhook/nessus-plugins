#TRUSTED 59bccc1d2e354b4051b2fc5ed84bb1f779aff2808c8607a85fba2472aae02dfa9d8e663bc368232d7bb125d5699412c283942487883007f54d4ac465593330a5474084bef927b9670f2f2268a72e55f8131242bd3cf17cd1197f0f29bdea56d2994431149a4166af2444090c080a3256e7fd490731b1b7515fb7d21379dae9820b7998a09772b0394e8138f0ce57dc0cb393db44d2dc6fccb36e76affed3e6a6e72d594856edd01c2fb93979b8c4a13d79a3ee78aae79eb272ee24c6a040b79d938873ddfd0e0e33d8642573944dccab275a61845ab578ded76ceb38efa742e9658b03760fe814652faa9dd445416cb96b1894a1caddda83ec4bf84a385c905a74c32477f36bff51acd9a7c3c5ad77af7b65d9afa382c712e2fe7dc043d50477e1816932161d4566a981ba82e2c4a5dd926666905c2a58d7c21ba8c242999177c4012a3c1a3c22de949d0bc84a190b84c49c382bfed3053c6a48501005cbe89219964a992017e9a43d734951c971c7795ad0161bcba6811c0b491a653dde44a35c932c1281f6bba534c6efa7a4cd8c92660a6bf1bc561d16e2904868dabcf150eb17db084a98a5a02bdacb004cf78f21c1599deed9684f0fb2213e46f8dedfc87cd00d9b0e88c2451a4422c1dafbe38d11004d2bb0812679389fc3b266ac46ad33bb4b6b16ffa78bdbb77ef38b15eca96d7567ab0d1fe5fbe9002dc3a188a524
#TRUST-RSA-SHA256 ad632356498cc92a38b0d8b677005cac664965ce1feb1546e55f01edbe78cf52bf2cdaf04f165d90efd95a8c8b4182ee36c1dcdb5d8b21aca6ffe5c37bf8b0008054fc5760f054f7ff9fab8f0d50c48086de05e3b7f1465201543cccbb20c4d5aad2d6b0656252acd9ed14fd9a8c0bb714886e3d6a9a1b1e17b412ad3abfe6bc92591efe7c5323754113f4b3dcf2337a2f8415b083da521386a8e91aaf6a754d95c375ee34e6cabf7edf2bec474d4b304109a7d820fff3e0a3cc13fb591a8cc9f2a24fcf1c504939d7a9d334b4dcaabafb1b005f9fc73b790217e66cd27e8d04b04011a3ae880c0eb8fab8067ddc3bd42df6df216f6f241010d584b103c2f9c569ebc0f542fd87076a1f7699cc06e06952d2f03d83f756af96a98de732a12913d7fb59aeaa7d493fda72d56e795ca3fe76e521f9fb8e912f18c9f1f96102038e78abd7c312831c0e1919fb9d2559bc12a3a06c41980f7f141a4dc7b7f2736ad628e66ca95503bce3d97ac92e133c8e5169c413b3159074cdbd5452d504232a3e7b95f8a0f0dc6aaf95d3a3c419ca625878ae8a3ea3633a5f4e884d64f90bd11f571715d98da5af945cc4223d48141f4f324b42b776ff790c9da248f7a09acfa4403c00afdb37d2a9606582552f66e28bf277d1168820a80dea2579c32469ffa4752ce41e0711c7beaa095364696fa3c464a14b758feec8d5fcb69fe95ad2a689
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161191);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3549");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp56719");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftdfmc-sft-mitm-tc8AzFs2");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software < 6.6.1 sftunnel MitM (cisco-sa-ftdfmc-sft-mitm-tc8AzFs2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the sftunnel functionality of Cisco Firepower Management Center (FMC) Software and Cisco Firepower
 Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to obtain the device registration hash.
  The vulnerability is due to insufficient sftunnel negotiation protection during initial device registration. An 
  attacker in a man-in-the-middle position could exploit this vulnerability by intercepting a specific flow of the 
  sftunnel communication between an FMC device and an FTD device. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
 number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftdfmc-sft-mitm-tc8AzFs2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9c4645c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp56719");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp56719");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3549");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(326);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  { 'min_ver': '6.2.3', 'fix_ver' : '6.6.0' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp56719',
  'fix'      , '6.6.1',
  'cmds'     , make_list('show managers')
);

if (!get_kb_item("Host/Cisco/Firepower/is_ftd_cli"))
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');

  reporting['extra'] = 'Note that Nessus was unable to check for workarounds';
}
else {
  var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  var workaround_params = WORKAROUND_CONFIG['ftd_connected_to_fmc'];
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);