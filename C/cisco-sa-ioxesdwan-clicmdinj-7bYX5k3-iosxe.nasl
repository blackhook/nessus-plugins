#TRUSTED 75f0d14c71f0089fa89dadac487d996aff0de67538fd2ba535cc08c48c154041b925fec8a1ea9ee2afb05a1f677a70bafd525c03e710aed1d515a0b2ace861a517debed689ff5941ea86e6fb4718bb5687fb43fd0efa4165f36bd860d6d466969b4b02e1af3f8046eaeff4e55802af112df51b7af8100ff0c11511643ff1c92e62abf9f0c906e3afe3f54b5568812c2226d092cd41b82e1eb0d0a75effc4517f40a020bb1199dfad704b0c87c8711a1f4145f6cdecb1569a4f4c98f0dd5aea22afc9d1f6128c3926da488842dcc91111ac36a25258d0e24f7a718ebbe766b30e462fad739ede50f79f6ff169d5a785753ae0eb745ffdf67e308002c23ceaa4cc9ee6cd00a5d01519977344990b6effca4ec1ece2b94686beb7e8660c51b093d0d786b92668aa5e198350af9b2f93456d7e457384d0518175a863fd3d3febb5fc0cf8097b8c99227047e0c03cd51bdfe2a5075b866960c550454a07aecf1241a1b31d73d46c6627322f1f58e3ed64a603d3874db680492fbdab82edbdb3b7adf760b33a62a1d65b5652c3c84cd0f027b3f9b70a834d4d8e8e61edadcd5ff8bedfca5590732cea6e7cf77f46d7c3d1365b2865dc6fe1a699ecbffe0c0c153f218de52b1f6d5d453c8430b3346bcffcfc0744d7a43da39514d5477e81c9610248ab059be9069a8aa3fbc891f86fef6acb18be2334b8860f4ae1975317f7bf092f81
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153564);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/03");

  script_cve_id("CVE-2021-34729");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw54120");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ioxesdwan-clicmdinj-7bYX5k3");

  script_name(english:"Cisco IOS XE Software SD WAN Command Injection (cisco-sa-ioxesdwan-clicmdinj-7bYX5k3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ioxesdwan-clicmdinj-7bYX5k3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a472ad56");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw54120");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw54120");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Affects Cisco ISR1000, ISR1100, ISR4000, CSR1000V, and ASR1000
var model = toupper(product_info['model']);

if (('ISR' >!< model || model !~ "[14][0-9]{3}") &&
    ('ASR' >!< model || model !~ "1[0-9]{3}") &&
    ('CSR' >!< model || model !~ "1[0-9]{3}"))
    audit(AUDIT_HOST_NOT, 'an affected model');

var version_list=make_list(
  '16.12.5',
  '17.4.1b_CSCVY09777'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvw54120',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
