#TRUSTED 04d41880dccb6b7e789fb81eeafa2eb3faf57a241c355b83ee1a4dc5ee10085b237175852cbca16c5bafbf293fa131e98c26fe1886a4f62521104668fb183ca22fa404e0144a2e96a85793fa236217d7444244e924841f8e5832bee329825fcbaa208fe393c1def449932edc925ff620c0666e7746bfc219037d0afecffe97f38f24581237fa4d3d7c42a2a189bc5964ceda35be58080364229edb47f5fb6fdbb8a56a58b6c46208eddb45d565735c1fa6a04b1c1f998f9de065b66e0b2a99002dcb8f9e7bd554c1d22309ed41886774084e15784fcab261beab3bbbc9091c46b5ed9c9652d65123e00a5b861955354822959a5cdb7b4ecc8c7b2248ce1af906df2db370cc1330192c878773954127eae4f9753c0216e083aa72015fdab77f12e0b06f26efc6439217fdbd551ca8aab1c770a87902f0f2380f903671bed38963e4c64f362b84077914daa26ca8aeb3d8839746413d4694806b8982a644a884f1a1484b26ab0cc4798df321ceaf5fea76e62ba481dbde7ea70c9ad0797a906df9e01b73e05e79d9784adf2cb6a3f8149197f67d1c0bc94dafcc7a883456a034d6fba34e22eff073b75a777d2dd5936411959d5e64fd2766709b3c33feb164b422996d663ce5e67f2b5af8f344ce699ec3f98505af4923e51bbc45b6756156734c5d1ad89edb91836605dd489298c0fe8b2c9457963d5ad8c667b0c0a40e181dc7
##
# (C) Tenable Network Security, Inc.
##
include('compat.inc');

if (description)
{
  script_id(139604);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/27");

  script_cve_id("CVE-2020-3525");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs42441");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-pass-disclosure-K8p2Nsgg");
  script_xref(name:"IAVA", value:"2020-A-0058-S");

  script_name(english:"Cisco Identity Services Engine Password Disclosure (cisco-sa-ise-pass-disclosure-K8p2Nsgg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a password disclosure
vulnerability in the Admin portal due to the incorrect inclusion of saved passwords when loading configuration pages in
the Admin portal. An authenticated, remote attacker with read or write access to the Admin portal can exploit this, by
browsing to a page that contains sensitive data, in order to recover service account passwords that are saved on an
affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-pass-disclosure-K8p2Nsgg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75e36c45");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs42441");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs42441");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3525");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '2.2.0.470'},
  { 'min_ver' : '2.3', 'fix_ver' : '2.4.0.357'},
  { 'min_ver' : '2.5', 'fix_ver' : '2.6.0.156'},
  { 'min_ver' : '2.7', 'fix_ver' : '2.7.0.356'}
];

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
var required_patch = '';
if (product_info['version'] =~ "^2\.2\.0($|[^0-9])")
  required_patch = '17';
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])")
  required_patch = '13';
else if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  required_patch = '8';
else if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '2';

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs42441',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
