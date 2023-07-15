#TRUSTED 5f0e1406d56ad65b6fcbf535f6dd65d7cbed463b8364a0c4234be9eb9d6194ac767a96f28d863f8d2a4ea5b5caa55fa137353f0f765fb5a57e9f2d7ea830042d2c5a2c8abf843d3638d4a2d7a74a2641e4d2633d4c68c52d8f13872d6e9045161068e2e6d7c4e4e438c8b6e52d208456b51e5c5444b35cfe3c2a287fa55ee058ef174133243b0c94974d185ee22c856c6f21adf3f97d22dc42f05f0b4e5bd0f0cea622520e998b0053d6ab7921df7dcb457d0389bfa8c9b89b2c4814dae4192240f86763af3aee2d5f41deab316ce1f7577a8adb733487cd71f05e4e3dfa5a2f8c56bd872eeff4c48215d591ec49a46903bda0b72e4b238097a963fceb83690be9185b01cd48cf154bef67b091de23207d76eb42c2bf40c3a9a8aed7f68430c8801540e3ce77094b3b6e9763e22344721b5e18d177e040ac689dc5c95876fd10037006f49fe45cf2e7eda8f5a46594c7c13d4e1c908001fc0202b09161ca6a235c3c1cdfcd22994dca5d2dfc8b9e5ed9171ac4bdfe9a93e9689adb6667f5464d3d60836b80a8c95801d955b16b411f63aca7c65eeb3b00dcabdf4dd65aa7a961de0fc7a72bf667d575b0573e560f766019ea3538fffaba872b4fc149634ec212541159b2db3b3df840f2acffbc1107c04c0adaf627deb6855cfdba164e713073095db7dda752a2a0c1bfe05d0d29c4e251e023384f9c1ac5d44556800554410d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151662);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-1603",
    "CVE-2021-1604",
    "CVE-2021-1605",
    "CVE-2021-1606",
    "CVE-2021-1607"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv95150");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53652");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53661");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53668");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53683");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-stored-xss-TWwjVPdL");
  script_xref(name:"IAVA", value:"2021-A-0304-S");

  script_name(english:"Cisco Identity Services Engine Stored XSS (cisco-sa-ise-stored-xss-TWwjVPdL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by multiple stored cross-site 
scripting (XSS) vulnerabilities due to improper validation of user-supplied input before returning it to users. 
An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, 
to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-stored-xss-TWwjVPdL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc309fe0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv95150");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53652");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53661");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53668");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53683");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv95150, CSCvw53652, CSCvw53661, CSCvw53668,
CSCvw53683");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1603");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'2.6', 'fix_ver':'2.6.0.156'}, # 2.6P9 
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'}, # 2.7P4
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458'} # 3.0P3
];

# Double check patch level. ISE version may not change when patch applied.
var required_patch = '';
if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  required_patch = '9';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '4';
if (product_info['version'] =~ "^3\.0\.0($|[^0-9])")
  required_patch = '3';

var reporting = make_array(
  'port'           , 0,
  'severity'       , SECURITY_NOTE,
  'version'        , product_info['version'],
  'bug_id'         , 'CSCvv95150, CSCvw53652, CSCvw53661, CSCvw53668, CSCvw53683',
  'fix'            , 'See Vendor Advisory',
  'disable_caveat' , TRUE, 
  'xss'            , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);