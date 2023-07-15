#TRUSTED 27e3574fb5dbdba58b6736327a8ae9246a042707a93067897a0d10ca2dd392f4470a06ec7fbd748cf2dcc8de20d10b4cc89357e5d94e194c82c80de2d0582eafbe92c06543f6a68718fbd449029399bbd9a50c361c347dcd6a08fff95b8651153ab9eb87cec5d8d68486f895608f3aa3d94513165e6f05f9b49688173f8fc7514a3a546209554d4a67b55de33deb91a3e7725b502fc11267e4f1b0575e9ffa9ed900aa6994c6a1195574477fc009811fd47560d89ce8e0dbab351d42ac28263706b69845032070b4a26ea20aff64b9b4c78f85330ca89a553c77875331d5a76f49606686541fd45e08ce8fd9f2a936bcd736b49a69d4fe523c6dd238a1a3417a972d30ab62edb83903337c86f2ad939e5952dcb941176033652725dbcefd006450f70cd62adc1fd0aaebaa147ca31ba7e056f1d6eb30bfc0a921792435d80d5d0fa11f7850cb19f8e4c94456dfd66f15b4b745a2a3f08e1e3daa054a06986592a789d83ac1f57bb3e4180ef54e2f0390daff47f8e393f454a9ee98ac4ceb19a505f2b9ca9e01a0ba26ce88d5e2d32258344a7dd40d7526eb8839ca362f1634188e320664122deff0bfeadcf5c1383e13ca7113779666c760f04b131b815f2448a0d2f7b9154c43ee2effe1a9e01ae9934a94395f62fb337b30bf35dd11e401fece6fc1080e6e2312f095e436d8bf901613f872ace411c4957557313a34297511
#TRUST-RSA-SHA256 7993aee08f4af2eeb0526a0f6f3780cb83e21cbf42a86037d4ea5ddcecdb3b92b051380b0a4b050ed67f5cdf187456c07f394ed39ea7e9ca1b663821781826def9d01de2cef68c170521cb84d5f9175463ff8577bc252003e21857b4156d0d8f601491518bfb7bc71f4ec3ac8238ffa93530d7b34f3f2ebabd06112ebd3e4f7ad014c1e0b498dfba8c7c178a22e4c7559c101844050a6aa82131381cd01c5318dba6f5769a9c1be084a80a2d7a5b73dec4d0fe7388df99ef362d50e557a1af331e517df64887b3dd9c2fa3971860dacd6fb32857fd29c6d0920e5887768e2ac8baf8910fffcb24b638f4adfc959250046812d31cffea520c911ba944c00e5c5902e650d871651e844a213f5373a9ac6cef30154c55b6e8a8d86f237942a0da87736d6b501d6c377e82071ac8768824e261df2510c69cabf98aacc6dc714733f7a0152401bec4d1fc3a441e34deefd253fb3ca86d6e2b4037f7630460504655c5e73d893964edfb54efc7eea77c2c8ab3594f9a9325de97389ba7e5400436137d0cb211e6a4520a805e181d5cb11c7eab55dffc0a1c3b9371e0423b973f51740b5a38254e4cca8cd76f42d717cf0f979d8660582cf320dc81ad108dfa130d209df625941a7dcff3c710501d12adb3239c8b99ff557f86f036bfa7ed60aa6dc621516f250cc4fb713aaf6ceffb56690552e67c919340dfef15aa71aabb19582906
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137559);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3195");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr92168");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-ospf-memleak-DHpsgfnv");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower Threat Defense OSPF Packets Processing Memory Leak (cisco-sa-asa-ftd-ospf-memleak-DHpsgfnv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Firepower Threat Defense (FTD) Software is affected by a vulnerability in the
Open Shortest Path First (OSPF) implementation due to incorrect processing of certain OSPF packets. An unauthenticated,
remote attacker can exploit this, by sending a series of crafted OSPF packets to be processed by an affected device, in
order to cause a memory leak on an affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-ospf-memleak-DHpsgfnv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74b6a456");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr92168");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr92168");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

# Advisory mentions a GUI config check - plugin is paranoid because it's not checking this
if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '6.4.0',  'fix_ver' : '6.4.0.9'},
  {'min_ver' : '6.5.0',  'fix_ver' : '6.5.0.5'}
];

# Indicates that we've successfully run "rpm -qa --last" in expert mode to get the list of applied hotfixes.
expert = get_kb_item("Host/Cisco/FTD_CLI/1/expert");

# This plugin needs a hotfix check. If we havent successfully run expert to gather these, add a note to the output
if (!expert)
  extra = 'Note that Nessus was unable to check for hotfixes';
else
{
  # For 6.5.0, advisory specifies the hotfix name "and later", so ver_compare is TRUE
  hotfixes['6.5.0'] = {'hotfix' : 'Hotfix_H-6.5.0.5-2', 'ver_compare' : TRUE};
}


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr92168',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes
);
