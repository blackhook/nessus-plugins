#TRUSTED 67d8059ef6de563f229307ce987472663843d7bc1abc2394ed1d3e50b98eab38cf4ebdd30ed5e7ade25b3669dba3ef487ee1c1e5b8ab4362dc0fa98e49c75f7916f58f697471506902e3b37c95fffbb0b4838051dc20811b32e193bfe2df8a291e162862f055d0269fb97861b8fa457c1030404e2c8f2a54b846c9724248216ccb4c780fb2a8e1196937199bc59ca4fcba8353a9a2b905d6960f8adf80f78ca9abc047c3419979d37bffecb566afa696a8504538b8fd63ac8d4d9d068e6771f7006ef405f0ff07a866b523fce446f565be381eb50e9af0d38d8ded74c04d7adad2461a6825431c40bba9e5b7e679dfac379dbf857ad32d65de055e52bca3d925585416bb23f1e782d4e883adab427b3d94135bf78bccbf89e4ee708708323a9774b5fc3699d732fb0b2e4ff07e8731ec796cf46f2ba1def4c8cdfd395c42fd5aea9618069b67a99acdd5fc2131640acf5baf097b5f45691a6c443b67bf3f49a504662d18482ee711f046e59b8154e7268c90e708fd6e204d7203e3a07e4e06302a6f9f71530bc98b3ddb380ce2593b4167887ccc9be51d31773580a4687e02f868d410239ef708e2b5204319be1373dbb6b10c5293051029dbc70e9faa8d7280b266c1fcd9eb5aaacf7e620a48f84af1e16ebf59c5be33e6b0245313c358962491b096b93e1e1974e76d33954664e358be946ddedb703c0ba0a9533d04c557b8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147763);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2020-3372");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo08423");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs21703");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt69529");
  script_xref(name:"CISCO-SA", value:"cisco-sa-emvman-3y6LuTcZ");

  script_name(english:"Cisco SD-WAN vManage Software DoS (cisco-sa-emvman-3y6LuTcZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a denial of service vulnerability in the
web-based management interface due to inefficient memory management. An authenticated, remote attacker can exploit
this, by sending a large number of crafted HTTP requests to the affected web-based management interface, in order to
cause a denial of service condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-emvman-3y6LuTcZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91343d15");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo08423");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs21703");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt69529");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt69529, CSCvs21703, and CSCvo08423.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
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

# 20.1.12 = 20.1.1.2 due to strange versioning
vuln_ranges = [
  { 'min_ver':'0.0',  'fix_ver':'19.2.3' },
  { 'min_ver':'20.0', 'fix_ver':'20.1.1.2' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt69529, CSCvs21703, CSCvo08423',
  'disable_caveat', TRUE,
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
