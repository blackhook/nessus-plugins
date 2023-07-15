#TRUSTED 2d011d842301d1b259e6b8ff57a8d39f201e9df40d669b42067e2ec4876babe8b6921e42d1af892c9e3578fd5773fce28f2383481d7a69f11ad580e54b28f3705a44720207abf26cec529d7694315401c11d246e85ce3c3b27b8b66c864c3ce281b8fed9731e1206738ae698e82720658fa1c37d7eec596ea95b54031b4df31c43acd1b520eab9d7bc432233ea34c215248a05907a92f7084e83668570d4c4f3f4174c48e702f288731a8d416a3b466637fce568fd0603f8d3d75372b39121b7e87f9415968341be0045aab8ec91b75800ed6fcc720d8a034190ef5a06efa3e3d483bfcef4f2506e19776bac686a14f59ba0f926428fe322bb65c7fa16954177e596cdcf2ae852910a9b5b4188263bb0a69c462c06b79eda8c26004a2d6cb12191c160cf46e90b8eed5d4eff6378383e6ef15111f4d724cfc34dddbb51ac4d30b478c0ea87db9a6fbca9a454c60832c322317287f88bd457d1d5c29175d2579c306570041dc43e10b4c8e13509665ef64d51c10c4219c04d9ccb04c0c28380b42e5e66a8f1446e3793101c1e1dfb597328a415bee68519c019beb7ba15aee71a79e6af05a258ed4b500e2fd7468dad27ef33ed37b692aadb9931faea64a5f01ca25fd79f1c7d5d3c1077024862de53faf5872e6a15c45ab038e0246abc6c826682a927a3be1b19f0551447652d3f2683e1326ec65b4a8ca585144ba6ffb6fef6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102364);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2017-6747");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb10995");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170802-ise");

  script_name(english:"Cisco Identity Services Engine Authentication Bypass Vulnerability");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Identity Services Engine Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-ise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e45bc0b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb10995");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvb10995.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Identity Services Engine Software");

vuln_ranges = [
  { 'min_ver' : '1.3.0.0', 'fix_ver' : '1.4.0.253' },
  { 'min_ver' : '2.0.0.0', 'fix_ver' : '2.0.0.306' },
  { 'min_ver' : '2.0.1.0', 'fix_ver' : '2.0.1.130' },
  { 'min_ver' : '2.1.0.0', 'fix_ver' : '2.1.0.474' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if      (product_info['version'] =~ "^1\.[3|4]\.0($|[^0-9])") required_patch = '11';
else if (product_info['version'] =~ "^2\.0\.0($|[^0-9])") required_patch = '5';
else if (product_info['version'] =~ "^2\.0\.1($|[^0-9])") required_patch = '5';
else if (product_info['version'] =~ "^2\.1\.0($|[^0-9])") required_patch = '2';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvb10995",
  'fix'      , 'See advisory'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges, required_patch:required_patch);
