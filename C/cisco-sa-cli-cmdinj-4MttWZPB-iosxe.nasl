#TRUSTED 5bda8e1cf3053bbc7f67ee27d33e33286534d6cacafb8bbd72af70b88d8e1a81cdbac48e05e0c3718fede60bb5e663a57db230db2f073cb260a729dfd4615fdb2d6cf848f189839f0aa50bdffcc341a8c913a392be0232679659685f8290227dec39de96cea047772d195012ce7ad9f11f2cfb65a7fa2f06ce3874203d2ba4d2b3d43951949d26329d2f75489ef71764192bc959740d667cefcc5de23d0c25b7c4d4e9c657b0df4589b6c3c5eb65f66b33c1cdf67cdb3ed2a5e383d7746384aa6048a2bcae7be316393614a183c8d5d203179e20ea2caa91fd59cc915e7c4a960265579b081c02b9b682a60bd895f9ee3e81b00d985e6e108c1a3c276285ff047341a370f2f03a3c3fc7bc41a404e17181bffc0014973d7d96357f65356755296b9c81ff3b610f6242cc4b738d2d07d0f141fc0f7bcd3def90b973e4afdde863cda217e6a938f9a8101d366d009beacec0037764b9639503f817b08b191203212cda6dbc34fd7fbfef8d6138d5b178d9774fd52dd55ce6ad93cf55ecdcf2127f34668765c97b5eec3c496e847d42658d7c740678ebd63bb1e4584a23bf0cb5f96610f63c14a600de8808d690472bcadb9c2dcaab6f77568be8be2fffecbc447ea90770cacf9cac2fc24bbcb43cf1795cb5cf084974e03daeefe0fb06946b101e6392a0bc72fe650b085a3dba32c0de74a379b2b98e2ef4ab3b5605b2f0d7c60c
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156884);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/24");

  script_cve_id("CVE-2022-20655");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm76596");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq21764");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq22323");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58164");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58168");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58183");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58204");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58224");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58226");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz49669");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cli-cmdinj-4MttWZPB");

  script_name(english:"Cisco IOS XE SD-WAN Software Multiple Products CLI Command Injection (cisco-sa-cli-cmdinj-4MttWZPB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by multiple vulnerabilities.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cli-cmdinj-4MttWZPB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e56d38ec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm76596");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq21764");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq22323");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58164");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58168");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58183");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58204");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58224");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58226");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz49669");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvm76596, CSCvq21764, CSCvq22323, CSCvq58164,
CSCvq58168, CSCvq58183, CSCvq58204, CSCvq58224, CSCvq58226, CSCvz49669");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe_sd-wan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

var version_list=make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4',
  '16.10.1',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '17.2.1',
  '17.2.1a'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvm76596, CSCvq21764, CSCvq22323, CSCvq58164, CSCvq58168, CSCvq58183, CSCvq58204, CSCvq58224, CSCvq58226, CSCvz49669',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
