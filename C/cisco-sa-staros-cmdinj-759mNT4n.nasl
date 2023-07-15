#TRUSTED a3e1e51f8ceb94633f7c3115679996b5c06a03aa3109299419de51dd7d497d1d41301ba9585e8f239b92063e8ab6413a31ec30f9d6860af69072c163937201d5c9840ee9c3d319773314c674b48341fa49680e6b882d76fd0a67720e01c315ec71a0cc129df1efabf0c0cab1cd86cbc72a3c5699db2d35d15f7fd34058fcea2baac20d2af22a20fb933be7605c5a0704678e0b0bdcf343fcf21870ba4861af89b1c7e666206e123da844cf269335ee601e12fa650d751f7e79dbd5a478c313045a457df8238ea0ae388f0065570b36f3bfcf475d171a5b5703434aeb12c3356a04bf3a1c36d57172b5fc497d6f7b9c6d1d01b3e687c1e20a8311af4ad9b3987a25675d6b2c7ac778917210b978a3c3ca2ea391977cfd9c7611fd59df4d119527a558835dbc115008ce06330502edd6324a6438ee68c23308c6a0b0308c1c311d33253904b2d0309c2556d27f25d3c12ff3554d81d0d352beeaae8d8c8acd5359fc357d303c4a1193a9552a74381002835ba94014933695c1185bc0bb77dd33d23fea4c4196e1efea0e5aab0c217c10d7eb30bd8e771a06c1f60efe6f68dee1cf08d035f44f106c066eef3db416c2d209e762e9930f51facfa705bfe235b37ee51d212ef2c6f7aa5379ee2db209b3e6d6dd7fdb7ed0a5e7ffcddf41247ac764b7c43e133838138112f84e9280754e1fee9b72e7f1bea356a1a2014705b01c9e99
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158586);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2022-20665");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz22969");
  script_xref(name:"CISCO-SA", value:"cisco-sa-staros-cmdinj-759mNT4n");
  script_xref(name:"IAVA", value:"2022-A-0098");

  script_name(english:"Cisco StarOS Command Injection (cisco-sa-staros-cmdinj-759mNT4n)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco StarOS operating system is affected by a command injection
vulnerability due to insufficient input validation of CLI commands. An authenticated, local attacker could exploit this
by sending crafted commands to the CLI. A successful exploit could allow the attacker to execute arbitrary code with the
privileges of the root user.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-staros-cmdinj-759mNT4n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cae2bd2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz22969");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz22969.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/StarOS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'StarOS');
var model = get_kb_item('Host/Cisco/ASR/Model');

# Normalize characters
product_info.version = toupper(product_info.version);

# Affects the following models, but we can only check for the ASR model:
#   - ASR 5000 Series Routers
#   - Ultra Cloud Core - User Plane Function`
#   - Virtualized Packet Core - Distributed Instance (VPC-DI)
#   - Virtualized Packet Core - Single Instance (VPC-SI)
if (model !~ "^50\d{2}$" && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'StarOS');

var vuln_ranges = [
  { 'min_ver' : '0',       'fix_ver' : '21.21.99' },  # Migrate to fixed version
  { 'min_ver' : '21.24',   'fix_ver' : '21.25' }      # Migrate to fixed version
];

var additional_constraints;

# Constraints differ if there is a version with letters
if (product_info.version =~ "21\.2[23]\.[A-Z]{1,2}[0-9]+([^0-9]|$)")
{
  additional_constraints = [
    { 'min_ver' : '21.22.N', 'fix_ver' : '21.22.N6' },
    { 'min_ver' : '21.23.N', 'fix_ver' : '21.23.N7' },
    # The below don't have "fixed" versions, but we don't want to FP on any new versions like this
    # Versions acquired from https://www.cisco.com/c/en/us/support/wireless/virtual-packet-core/products-release-notes-list.html
    { 'min_ver' : '21.22.UJ', 'fix_ver' : '21.22.UJ4' },
    { 'min_ver' : '21.22.UA', 'fix_ver' : '21.22.UA4' },
    { 'min_ver' : '21.23.B', 'fix_ver' : '21.23.B4' }
  ];
}
else
{
  additional_constraints = [
    { 'min_ver' : '21.22',   'fix_ver' : '21.22.12' },
    { 'min_ver' : '21.23',   'fix_ver' : '21.23.11' }
  ];
}

# Combine constraints
vuln_ranges = make_list(vuln_ranges, additional_constraints);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvz22969',
  'disable_caveat', TRUE,
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
