#TRUSTED aa60c0819f1e63593cc122261ef702a9b485cca98b46aa3fea7592c8a96665ff2d94473ac1f880b4bf8a6a133b5a284da08799588baf36e71763bc53c875c72f7cb6f8cff4fa69f632ec3617ffd0018f1185c921c44f8667d0133359fb2be8ea38520cdad8d219426445505d1d0b5ffe8d1ff44eef4c8daa4c59768d219b9cae152d22bafb3c71f8db05507539ced564e9f6667223a2d8a6d4811bd0add08e3056be16afe368d0e6b3ada45732bdca5e7d5c2ba8eb36fee4946608380f6b10744d32624104602f5b6f3a7ef5a9f949e8d28b6601ee37a907997e87409c4ffec906167dec7aadf5ac51a06b864da3dec84b6e8ad3f299e0dd617eaf918cdaac95741e4b3023a991146ea379bdf3e794e7932fc8b8c0e37f367f36e6be6e9ed9c4496b490e0823283bb78d5366e84cad90737da93e7fb78b2ddb516d07e4ed794576d6fc76b42677e053a3a4dcfd1766016b98f317e3cca0d5ce230f537c3ad92ddeb090b0664bab97ee813d0ff6cee53f7efa6aab1c750fbe01e1bef8ba0328b438feb8d1da73e36641f58181f38cd541f48384d35b189003606f139146e5fdbf5f1d6eed808b6bd9d59f255d503a498afbc099abcabd6483889ccd99d04309793ab9b9445e365062fa3316a31c870fdb3818b7bed0e07609467f2e0d3ad990f89bdd739144042f606c272caa1a72b24580ff365cb54664e03fdb644eafc707cf
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150027);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/01");

  script_cve_id("CVE-2021-1306");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ade-xcvAQEOZ");
  script_xref(name:"IAVA", value:"2021-A-0248");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw48396");

  script_name(english:"Cisco ADE-OS Local File Inclusion (cisco-sa-ade-xcvAQEOZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a local file inclusion
vulnerability. A vulnerability in the restricted shell of Cisco Identity Services Engine (ISE) could allow an
authenticated, local attacker to identify directories and write arbitrary files to the file system. This vulnerability
is due to improper validation of parameters that are sent to a CLI command within the restricted shell. An attacker
could exploit this vulnerability by logging in to the device and issuing certain CLI commands. A successful exploit
could allow the attacker to identify file directories on the affected device and write arbitrary files to the file
system on the affected device. To exploit this vulnerability, the attacker must be an authenticated shell user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ade-xcvAQEOZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?937d9a01");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw48396");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw48396.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/27");

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
  {'min_ver':'0.0', 'fix_ver':'2.6.0.156'}, # 2.6P10
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'}, # 2.7P4  
  {'min_ver':'2.8', 'fix_ver':'3.0.0.458'}  # 3.0P2
];

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
var required_patch = '';
if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  required_patch = '10';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '4';
if (product_info['version'] =~ "^(2\.[89]|3\.0)\.0($|[^0-9])")
  required_patch = '2';

var reporting = make_array(
  'port'           , 0,
  'severity'       , SECURITY_NOTE,
  'version'        , product_info['version'],
  'bug_id'         , 'CSCvw48396',
  'fix'            , 'See Vendor Advisory',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
