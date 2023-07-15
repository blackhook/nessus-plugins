#TRUSTED 3f5859f38bbbcde8b9a9cdb3eb16e8acbbff16c1de22450c9567c83587350a7e0f86c93490992f4b97ff435089e069de081341fb821391fd6d032a5ac4f300dcaea253a54f9dbd729b9f604062e32c9960f4472ecb2c7e9b64be8bb9096c2a6bb6d98eb6082bf6e7fa4806557a09c286d534c3929d9c0baadd47cf14313b2ca7cda7da9ae9c554e4c8d8827faeaea6b62fe4402ef38f8ab0efe0aba20e15590c32fd4e279cfa326434ac55a1a35f867b36f8024056554a283d3228ae417735bf5d29af85cafefcf8f59b8aabd734dddfe41a9dc39dc0af87a177c756f2a4695fe99bfc865afc738fa7e8708b77f24ba68a205a3db0cff5e8ef325b9730933dc6fbe6f52910422f5c1c4f8f56f609b76c55d6bc483d24be8d981d4746bbf274ccbe2881801c37e275370f648c897784cd44d36443737645cf637cc13c47afabe9c9210225face5d10adb9360ebb6beac62c236ba2859e3e8f22fcdc93548b91b3c3d572e2c3b5f06ff0f428eb4f6ed75a3a9c4ab055a23b25aff12fafbe72e61ba0fd58b95022f834b7bc99fbeb662d9232ef85c8f32701184125cd446a5dbe7cddbede61584a03cad9285346be038101cc7e56bace21a3ff0dded28360b909b3f6c35f78c12776f01a3b14c0b385359538f169f64e7ded090030c27b49edd3931a962d221dd02a0b9de20fde1d74ed9aa615b44eb67e57015609a496f882efb3
#TRUST-RSA-SHA256 6dc4dc9a69521285691bd6c5de0c163a9593d95c6cc879b1423130ad449de19b5e213f550c562734659682448d0787f1b971012f4f260d0f293557608bdda1f54e71ece4511f4bdbe64deee50a563ffa368580acd2460008070b7397010ca0ce01f3a2545e0c1aab77deeb7ab1dd9864ab74af1bf040cb03168b3745fae9509ecf5831bfc5b2f53fdbcb148a9aa219eaa4c3dee8330ada580e01083430b565c65848a7387a9f68d5f4f96672696d0f497925839539d1aedd2d97572cb9726e00dd80bff15d195086c1c38468508ef43407c0a86f5d2b8d1bd10316422e5a1a624b294d2f9971813e7c45eff0119ecef6ea2960da1beaa06375839ce2abf9df085e76fbfefd7a9e78b872663270e5b99aa2adae7ccf48247fdf45f6dfb68eddabfe3f27504b81f9eb971012e68134c2eb07a88e79cc07eabb4f2102afe7bb13afd1b7c31d895fdfb8197c964e25c4a19ced93478abb6b23860f3022e919d9de23d8eb68d4658d988cf0f859d17874ed7d05cdee1b5906decb387f4e3be02be3f4e3851210aa578ebfe06ee78e96fc9364b86ed72462cfb42ed2236fc65923364478336357794892ca533e9337a1a3f353f746a0bb4edb288976ba4320f507c7a71bedf4440331392fa160b6d49d79a9acc93302fbe3beabf38b424fe78e595c4e790c0718d45dcea470615d7aea037977d4f952ff24afd54fb4e3a8d417ce9d59
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166382);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-20959");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc62413");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xss-twLnpy3M");
  script_xref(name:"IAVA", value:"2022-A-0438-S");

  script_name(english:"Cisco Identity Services Engine XSS (cisco-sa-ise-xss-twLnpy3M)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a cross-site scripting (XSS)
vulnerability due to insufficient input validation in the External RESTful Services (ERS) API. An attacker could
exploit this vulnerability by persuading an authenticated administrator of the web-based management interface to click
a malicious link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the
affected interface or access sensitive, browser-based information.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-twLnpy3M
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fda3f6ef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc62413");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc62413");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20959");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'0', 'fix_ver':'2.7.0.356'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542'}
];

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
var required_patch = '';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '8';
else if (product_info['version'] =~ "^3\.0\.0($|[^0-9])")
  required_patch = '7';
else if (product_info['version'] =~ "^3\.1\.0($|[^0-9])")
  required_patch = '4';
else if (product_info['version'] =~ "^3\.2\.0($|[^0-9])")
  required_patch = '1';

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwc62413',
  'fix'           , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
