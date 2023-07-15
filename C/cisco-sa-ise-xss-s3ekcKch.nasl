#TRUSTED 3d0dd3927ccfbaa9f965af6e5c7b9b0f4700f6cb24c2c9ea5c10b6c4a381be1131abd36239e10efbc47f306f938cd63e937430aabc4fcd0798bb6e50294f1c6e3f7597849edf577de37d8e475181417ef8232a9b6ed84f132c6df44eb8ca19545737f14640e74a7c71c0be60c62fff9687d6af79f732bb8548cf9a8f8a763f0fcbd937d19a5f38f0dc343f1160729ecaabf5ed4e6a31f7ce2390c66eaafb33c9a326c612b84396e49799215f3d580d551d87ac02960723901e56730f3b54856a51dc1fc06e9f2f073328a0d13245540f18c884e871aac413668552967727ef0701ef177bbcc7fe848c203d64269f5c049f84f98c04cc6c5e79ac94935937bfb03e0ac8733a3de6ac03806c4098df46f7ac35e2d35b9c7c3882d6ee73abb992555d887f0ea8c769ba8983c2c887e0305bf9561842f4e53302bd4a558833a95bf6d1ec2ea434a9dfa3f12a75e0fe45497ec649a066ce90aa41e6c1c36f85e09497fd6e7f701b4efd50c765077b81c2326647b099f90a4228243ab07215c8a085aa5c31cdeb03b35ffc1656f6c05c2271552503d2563c9bfe32908165601b9b68deff56d6034cc6433849da9031e73d8e278d059c06502f3652ac01f6508b46b6384bc9c24deda205cf50dcff47ae328efaa4d765ce92be753eaeb46deaf02581c250ccccf53f20f66d8835bd83ec4f5aa5ee4993157e953014918bd997621f5f4e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135971);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2020-3156");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs19481");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xss-s3ekcKch");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability (cisco-sa-ise-xss-s3ekcKch)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a vulnerability. Please
see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-s3ekcKch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d01707cd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs19481");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs19481");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3156");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

vuln_ranges = [
  { 'min_ver' : '2.6.0', 'fix_ver' : '2.6.0.156' },
  { 'min_ver' : '2.7.0', 'fix_ver' : '2.7.0.356' }
 ];
 
required_patch ='';
 if (product_info['version'] =~ "^2\.6\.0($|[^0-9])") required_patch = '4';
 if (product_info['version'] =~ "^2\.7\.0($|[^0-9])") required_patch = '1';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs19481',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);