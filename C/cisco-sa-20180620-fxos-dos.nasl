#TRUSTED 2d2d5f1a8230a20addd5512682fe861c11031608c40ec2d13b4dbc61446c873b50bea707c985e783b5369b44aaf9ab675717a1ad0734fc577af3b2796a9e73b1cc879d852e9ce1012a3e5d2fdaeb1826035fefd101b2414ff577e3bb244913a9256769098e1a19c7d8f135a712cf50a0919d0d6119d47bc667397d2202dfb9aef72db86716bc876f26a5d6f86328666a867c05e3210fb980154252b3c2bbdb1ef9b019b974690f7faed809446fb7bd05b28b280f167a5146da7752af02f514d7e653bcbc3257cf5869693b4de8f1244668d68f4920070b08dd4b1f72168c854d88c66d19eb4d2bac2823398236f66bce2fbdd608290edbffbb9ec6191432f1e01210a9eae5fad1f877e0b9e045867515a2103af48d085aad49c91c47777ab37c3e32083240f9042032d0c5af9ba46aaf6f6e647e1caf9a35a226ae08c6e7685ff9a4d7a32d41fa337cddc87de6e38575d71b2668733baa59ed80976e9a226a1d96eed778463f09dc2fb04031a66968ac8a156cccd8f8ed3ee37d13902d49ba12b857a850bf0b52019d326996e55651f93664f153c0e2e9e29f1120a80ce75dbfd40e129eee95b05f6b0013846403fd0b3fd95805af1ac6708b5e1f6678175bbc883efc4eaaf9a270a88f785f718d9a444cb128ae1ace74a114f82d1d69380e5f2a0a14ad417ffaa3d3bdbcfa5e5d0c47201fc90103b0710e45767f82f37aedd6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138347);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2018-0303");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc22202");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc22205");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc22208");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88078");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88150");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88162");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88167");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fxnxos-dos");

  script_name(english:"Cisco FXOS and NX-OS Software Cisco Discovery Protocol Arbitrary Code Execution (cisco-sa-20180620-fxnxos-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a vulnerability in the
Cisco Discovery Protocol due to insufficiently validated packet headers. An unauthenticated, adjacent
attacker can exploit this, via a crafted Cisco Discovery Protocol packet, to execute arbitrary code.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fxnxos-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f92e2bfa");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc22202");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc22205");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc22208");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88078");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88150");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88162");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88167");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvc22202, CSCvc22205, CSCvc22208, CSCvc88078,
CSCvc88150, CSCvc88159, CSCvc88162, CSCvc88167");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'FXOS');

if(product_info['model'] !~ "^(41|93)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver' : '1.1',  'fix_ver': '1.1.4.169'},
  {'min_ver' : '2.0',  'fix_ver': '2.0.1.135'},
  {'min_ver' : '2.1',  'fix_ver': '2.1.1.73'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['global_cdp_info'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvc22202'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);

