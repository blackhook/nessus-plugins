#TRUSTED 021f6ba4aad2aca29de52b7565a78a26746288a75e183e3fcb963332083038a9ee21654648f4d00c9bef858e82d99423027de7a3fa860368e27b66403cb527101ebbdf3dda38fdf2ad464162a9cf9913c3f0cea7dea0e5f77cfba50c9da2d81fa0abfa3e95b524f7e2739b755fdacd9333d22c64d85cf1002e8891ef3507803b4eb3446d46003292a466d62c26a4cbf39f0e5e59f89159502138048af52ade49d69be22083117cc0c732d4a6e8eecaf2cf7854c18077492026da4920feae27da86dd2786a62c0ca0bd7658e0d92b97c8b424e4e79a27f83498bb73d0b4677b1b110bd8801fa07f1bb2e6755f176c36ee23d1c4ee5474d4986269cd9f203c5b04546c4d79d13e4d67a01332d7aa8bedd5a4ddf5aa00e7c925c0046f1d843190a95b5ba5d41dcffbe432d20944b2a148951eea6625ff5b2f96a727964b98eafa8c3c2559c8225813b17fd29086b4893999b9662bd4ac253875cb6947c002fdc804f90e399b5dee8c676bd4ad3e53b3a9792d8abcfe5bc784f0f45c1d60dc5f7f7d638fc6442d3d1c306f996c4b9e7850a5e6c4b509d08f0801d73d41beeff29cd837683861673655fb32fbfb05d12d53b5e9cd17bb8e5fa59379c1d9c9056ad449016b0f1d1aa408b8d043037f4076163686b91fabf4f0c9475a07b36d7dd696d5e55c60616729e4546278f06af4430b5681a1debeca9e210d68ccff58c01e5d35
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147757);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-3406");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt71038");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanxss-z7bhvHpy");

  script_name(english:"Cisco SD-WAN vManage XSS (cisco-sa-vmanxss-z7bhvHpy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage installed on the remote host is prior affected by a vulnerability as referenced in
the cisco-sa-vmanxss-z7bhvHpy advisory.

  - A vulnerability in the web-based management interface of the Cisco SD-WAN vManage Software could allow an
    authenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the
    interface. The vulnerability exists because the web-based management interface does not properly validate
    user-supplied input. An attacker could exploit this vulnerability by persuading a user to click a crafted
    link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the
    interface or access sensitive, browser-based information. (CVE-2020-3406)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanxss-z7bhvHpy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a78d7319");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt71038");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt71038");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3406");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver': '0.0','fix_ver': '19.2.3.0'}
];

var version_list = make_list(
  '19.2.099',
  '19.2.097'
);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvt71038',
  'version'  , product_info['version'],
  'disable_caveat', TRUE,
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting,
  vuln_versions:version_list
);

