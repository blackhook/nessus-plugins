#TRUSTED 7eace58fed8c6428e7e0dfb4f07404337b4b8d4c7ee0c659300b327e2936b336afaf84986ff6fc1cfe138edd79edc75fcd71c53bc163eea29ab70cb9e8b405797984eed3c97f25ad70c8430d0f44a0469db8e4cf95bc6e03827395468bb45a328aab2b417db5bf8b7436969f89c2142daeb150f89935fd6cbfd8babab3dd5e5cff390619c9fd9d16eb0a69771e6b6603d64631fece689ad0bf29ffe4a119f09d35f7bb4850049e07dbe5c653cd07fb5faa40c4564b957cfdf1067c514cb419459d2fd6020bfc2bfd795aeb11fca4753547f40afeaad728769b4054bc19a0bab27d4b17bd68fc4708543beec40032159cc9d7f18bd06c6c3d1168a2c3860dc8e573f51108f4368ab9402c174f188963ce643d1088b8ef90ae11212153f02b67801a9ff2a0e28d1282789b3d725275bcd06c31f781267257a574c483e6951a292c0efb9b023c7ef630c67c730b6ead56f5662e4625616a0524d1945b46d40ccfdb4ba7b21271784d83bad3eaa32f1ff7141374c34ccb5451987290524fbb852b0723edfbd46edf8b8f9ce441a7b2e4d580a05b276a4e277e40897c3f8669053cf3a6106be238243622b2433dbf50e8d067aca6999dd75fb8457b25d87870756ccbd4f71583cc85096ffab136e84ee8cad6a14f8828194a1b9b627a926c4ad738aebe4ad28fb9daf79c558e0e7f48852a2153ebd967d91157d671326410803f8af1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126105);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-1719");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo10441");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-ise-xss");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability (cisco-sa-20190417-ise-xss)");
  script_summary(english:"Checks the version of Cisco Identity Services Engine Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine
Software is affected by a cross site scripting vulnerability. 
A vulnerability in the web-based guest portal of Cisco Identity
Services Engine (ISE) could allow an authenticated, remote attacker to
conduct a cross-site scripting (XSS) attack against a user of the
web-based management interface.The vulnerability is due to
insufficient validation of user-supplied input that is processed by
the web-based interface. An attacker could exploit this vulnerability
by persuading a user of the interface to click a crafted link. A
successful exploit could allow the attacker to execute arbitrary
script code in the context of the interface or access sensitive
browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # http://tools.cisco.com/security/center/content/CiscoAppliedMitigationBulletin/cisco-amb-20060922-understanding-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1596bcb6");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-ise-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4faa9a01");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo10441");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvo10441");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1719");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");

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

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Identity Services Engine Software");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [{ 'min_ver' : '2.1.0', 'fix_ver' : '2.2.0.470' }];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.[12]\.0($|[^0-9])") required_patch = '14';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvo10441",
  'fix'      , 'See advisory',
  'xss'      , TRUE
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges, required_patch:required_patch);
