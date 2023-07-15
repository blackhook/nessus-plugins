#TRUSTED 4e20d8124409ebefa00de8662ecef0cf74dbc81d01a2a9fdfdad8157357768cb04ee213600ef3641a098d1c9a55aae921cb5dcfc678a9d5f38bc0bc1af0138ae82f711771025283e2ac79dbb440b4acb32138a6db6fc10ec693beb25f58fa40adaf18deeb86b630bd6db6d99c1e7ba3f4b56ed56a7bd286a7fe8274892c905cf4b2bc062004b0c027d39d79454f723afc2370c86b3fe49d055e20ee1f41f8f451edfb8ba81862429b06f8c9391b29f3e1fba2f3abb2c6b46bf71b4f10e5d5505efb41da537417899881179e02b69588ed4adaf4cb9229e791a49bf91c74405d69f975cf6918ce41d216ac77c3eb5b51166d25ed7092ea27c9c47e54d81defcc318af042725919e2b701e7ea5be0d5c9260dcb0431f92e5ea54ff830c5056e952ada8755a28ff88c8ca217c0c329460b96e44bd0f24d8f9829001e76807442eb168c13cdfdb62135a05ddf3e3a5db2f3b1953fe675ca92181fbd629394631e1e845c9863b3d553cf409467864378a30bd2a13ed005d649849e96a6f3c89db914550e1580ea56553927e95bdc5ea164e24046f59c424aa20d4f28384b82fa544a1886eba918d4d0cc55365fdfb94e285313cd9297a707525695e21dd5dac734987550744ea31e90d76566c818badc255ddcd7652ab6fb343b2e7b5fcfa65ff33efd84c00533f74dfe90e792ccb90f4a86c54915714fdde367c85da72fe1ed33aa3
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130397);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12707");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp14284");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-cuc-xss");
  script_xref(name:"IAVA", value:"2019-A-0362");

  script_name(english:"Cisco Unified Communications Manager XSS (cisco-sa-20191002-cuc-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a cross-site scripting (XSS)
vulnerability. This is due to improper validation of user-supplied input. An unauthenticated, remote attacker can
exploit this by convincing a user to click a specially crafted URL in order to execute arbitrary script code in a
user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-cuc-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5a7d927");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp14284");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp14284");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12707");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Unified Communications Manager");

vuln_ranges = [
  # 10.5(2)SU9 https://www.cisco.com/web/software/282074295/147607/cucm-readme-1052su9.pdf
  {'min_ver' : '0.0',  'fix_ver' : '10.5.2.21900.13'},
  # 11.5(1)SU6 https://www.cisco.com/web/software/282074295/145230/cucm-readme-1151su6.pdf
  {'min_ver' : '11.5', 'fix_ver' : '11.5.1.16900.16'},
  # 12.5(1)SU1 https://www.cisco.com/web/software/286319236/146815/cucm-readme-1251su1-Rev3.pdf
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.11900.146'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvp14284',
  'xss'      , TRUE,
  'disable_caveat', TRUE);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
