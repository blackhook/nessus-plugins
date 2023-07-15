#TRUSTED 3f3f3392abd8cbb4d64c6511740f589bdf11acf206a2ac4e5b470cce7b8e27323e91cdbb7722d4cb9cfc0d88ca54b4d1e7fc0af5d82c56413d0ee7a1103201bebc0e1f2e721c2f36d4007ff5ad351ecaf3f19f57c5b7877d0a47a9cbc2f0b69d048285a3c1eeab05ec49ab183e1d9bfef9ec57483b588430739b60df5f2b308a373c812c9e8e4069cc474e2e81b1f239269647e75e82ccf471e94a5ca1ca256083f5040301ba7c5ad010d4600713cef8a41cc86318fd85e99306daa1a1400e1380165d343bbeabc290df273770f2354dffda85c51e2df03a2c455cf43bd9682cb0f6cdb69837dbbea65d9a0bea88d3f446f063830be632b048bd4eea159373392588cd8c37ce777c57bb76eb52826ef21e4f3d7bc613da5230b055843c3eb0b7903ec8d70d32023e7d2eb297329c93d843c80e91679f80d8e2768e0b83959f588b50754843d05cfd8d86c9d94b75d308676ebcfc3599503feb7e5bdbe71a00c8cd2fcecae41960b984a63ba62433dee6f20b098f6f61178bc3e724fa8d73de0d39f76c328b2fa149d547dccf3f9c5073bf59fd96fd991dca549f05d452cabe9d5c789b9daac3544a48eda454a1686a04648c4b8f79f5197154b2deced57e73012f99278962a63b06f9d69d8f203e468056b7133faf6e115c0ac10a7f8bc473aff5dcf7883582bf1b2bd95fb562e5734d151810fbdd4895b6816bdd6d28aaf496
##
# (C) Tenable Network Security, Inc.
##
include('compat.inc');

if (description)
{
  script_id(138152);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/27");

  script_cve_id("CVE-2020-3340");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs96516");
  script_xref(name:"CISCO-SA", value:"cisco-sa-mlt-ise-strd-xss-nqFhTtx7");
  script_xref(name:"IAVA", value:"2020-A-0058-S");

  script_name(english:"Cisco Identity Services Engine Stored Cross-Site Scripting Vulnerabilities (cisco-sa-mlt-ise-strd-xss-nqFhTtx7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by multiple vulnerabilities
in the web-based management interface.  An authenticated, remote attacker with administrative credentials exploit these
vulnerabilities by injecting malicious code into specific pages of the interface. A successful exploit could allow the
attacker to execute arbitrary script code in the context of the interface or access sensitive, browser-based
information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-mlt-ise-strd-xss-nqFhTtx7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01e187b5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs96516");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs96516");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3340");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/07");

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
  required_patch = '14';
else if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  required_patch = '7';
else if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '3';

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs96516',
  'fix'      , 'See advisory',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
