#TRUSTED a9e90eba34aada7972432c67f4de7aae40b92a5034a355f5931648a52b751ea40e5b0e6b5ef14444d6a7e2cd55b89789542e35247225f18799bd9e049897fbb44b671a17b0337e439652ced4ed1efef47fd31d0d5d6f62a070baf5252d502aaf25dc1e33e1b75251acf491742a81829cc7ce146f978254477ffd92e29b4f6d0954a02834cdb8b1aed6e520cba023fd448efa7edf72227db16f1bbd1b241af417017e4c4b2f82b2c4ed405dcb6fbf8dbe4306a28fa6e4f5dafcbd3cab973dbd40e75678cb3983593ee8a986d6f3a524ca077e44e7fd755973cd1ec8d017107e32574083bbd27a1949e387e6192a398ab8694bafde4c0a8584f9a63f546ec2c9467fb2b17e90dbe13cd2c510c13f741b5b504816f88bc33ef3b77c6cc1c30bff9ef46ed2ad57a2fc999a920df0e220db6411106e1cee11121800ed47989b5afa202fcb651cb84c54d90c8023363d04dc56c47acbded6d737cbf55b96b9d08e563701a6835964e4d719e9b59e896edd8ef5c26cf41802946614e46282dd3765728137a5140ee5fbba46acbbd733ef052400c67296c7543d0240377ae20a8d5ba7d70c483562996240acd1a110bec9e5e7302cd3ebcd4a97e67ae15001fd3096d638945dd80fad405dd266335093d2adfc119a4bc5a3aaf5c5cad0ecc22443d6c57da86fab4ab0a9fde0f4db75c8ce080c1f983efc7b26d32872e701f57f63835b1d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131020);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-15281");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq52317");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-ise-xss");

  script_name(english:"Cisco Identity Services Engine Stored Cross-Site Scripting Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a vulnerability.
A cross-site scripting (XSS) vulnerability exists in the web-based management interface of Cisco Identity Services
Engine (ISE) Software could allow an authenticated, remote attacker to conduct a stored cross-site scripting (XSS)
attack against a user of the web-based management interface of an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # http://tools.cisco.com/security/center/content/CiscoAppliedMitigationBulletin/cisco-amb-20060922-understanding-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1596bcb6");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-ise-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1422c612");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq52317
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ac40bf9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq52317");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '0.0',   'fix_ver' : '2.4.0' },
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '10';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq52317',
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info      : product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges,
  required_patch    : required_patch);