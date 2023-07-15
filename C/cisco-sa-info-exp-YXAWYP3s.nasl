#TRUSTED 5dfedbbf54f1823d9f972fd939d1a52b84a9a2d200965539b383d47bb4abb03b3a6f2e6f0dc1b29dccc8ba8f6c3447e064b88576eecc32a509f26bcd1a6367fb42921074ef3535698d819c0d1e47df28f364cdf6eefcd51b62d044a4386849815d908ab37f591d1918a0c6a734f69720eed21dc1ac809ecc5967e60b35086d5514de2b5b224dc919be15a764259971dfc0329c7f6718ae331612b6cd66e302cd36cd8ff89032347b949f4819cbc86314e2b5ed52022e50a566ecda431fb2183f4d5bf82868827b6a6645ddbedcb2a9672132cda35fe2207692ef27b4503f36f86ee281bb70028f73baba560d3390e44273cf44699014006dbc20448779c0c25d31fedde71c214b1574c1b88b6a1a1b83515e02f23c371263403d86d32a0098080fddbf725c9dad96bac4fa3d134feb3fe074908798d5c6a60d7db470ab39b65a4f749882b89fe179ec2af0841f911d47769f4d460a4c9527252eb9388541e7e6e488a8e68c84ea9bacb8d40da2c7399553336010ff408e0d0f3cfda689e16730c1afef7303ee187bca375414854826c7ce551262fad24319a65b11ce6fc8f4afc06e8754f030af49d68cbc1d72e8aca79c61b42cda315bf91f23c48432f6793fe3d76f29feb0f2fb516f74d194aaaaad291260ad0c2f8522aba7f0b4c51d44899e9117352939e09b3281e7bad1d6197abb2f4961222e195e379c5197cd37ad89
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159758);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2022-20782");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz20851");
  script_xref(name:"CISCO-SA", value:"cisco-sa-info-exp-YXAWYP3s");
  script_xref(name:"IAVA", value:"2022-A-0138-S");

  script_name(english:"Cisco Identity Services Engine Information Disclosure (cisco-sa-info-exp-YXAWYP3s)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by an information disclosure 
vulnerability in its web-based management interface due to improper enforcement of administrative privilege levels for 
high-value sensitive data. An authenticated, remote attacker can exploit this to disclose sensitive information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-info-exp-YXAWYP3s
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49cb4c87");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz20851");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz20851");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}
include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'2.3', 'fix_ver':'2.6.0.156', required_patch:'11'},
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356', required_patch:'7'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'5'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'1'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz20851',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
