#TRUSTED 0b3e6cdade6399954760e3ef35bb0836bbdbd2d1e35214aec3a9fe9dc7711b67725974b90f69258dada9c7d2fe01e00946565ce757aac9b4f805e5ca83d29a432813cb5d24e795a9a03825a19939af77c70c0ec4b2fece690d49610a98eae6584206eb1816f18d2cbda0b99baa6bc8c142fca3d034844bda555dffbe47801cad22debd40e0f085e122b92beb1da47979634432f2387194b33d9d68521851fe187dfa30fe4168ddd7d36bed8d89e6135e2dff603dcd0bcb58a25f273170ca491dcb7d32e4f6da213f848dac4cdc1590f1282c4a53c00f9361db7da1ef6f80949caed8a5e3a661a97c5abdf734d3eb46ec2a8175c381bba02b9184c07c214453d31db3951f93983372b947a6a5ba1a7b637957afb58420d889040e91981f26b3e53bd372a630bef6a1de20e8517b69f44cafcc3312c5419a08387851551f13a7b9067be572486fc63f5775b508f106364fc2f1402833e7daaca496bc1404fdd5b7ab5015502d5fbe9630acd53e9840b134b36837ac957dfe033e494298e584fd1ea323d5bd5eae9d86435a9469338001864034d6af188e091a383aa32721a2ae126bf8d23740102ead831eab26292328709fd6306a5cd3ea9231641e274ef598e147dedf6edede1b875b3a0045bd089bba1bd6ebc705c49938b70bdbd1f0f24bde7623c8c8ebee6b5fd9276cbd337fbfbc7452ceb09d594f02bdf9afb5e49aada0
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145552);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2020-27128");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21749");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-file-Y2JSRNRb");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Arbitrary File Creation (cisco-sa-vmanage-file-Y2JSRNRb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by an arbitrary file creation vulnerability
due to improper validation of requests to APIs. An authenticated, remote attacker can exploit this, by sending malicious
requests to an API in the affected system, to conduct directory traversal attacks and write files to an arbitrary
location on the affected system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-file-Y2JSRNRb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae014018");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21749");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv21749.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27128");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

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
  { 'min_ver':'0', 'fix_ver':'20.3.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv21749',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
