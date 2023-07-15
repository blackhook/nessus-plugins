#TRUSTED 472a9b325ea9629dbeb6aee446b457349992a28dd8e3d71f81a2b6934b3edd20a58737a3ed13847ff438fb75009dc943debd60a9f40a58309ee910a389324c50d6ebea797a566a057bd8ba9037d359dd7566bf8cfa94d06f006b6f3223e18d35fb867479d9ce3f35c6e366430d09feb2b3ad2137e96ff0399550f8c59a4dbe7d6fbc254a106252e903863d8fcdb55b0cc8f23124af0adc9997e08e025d96b412f7451636045b9c574ff3df770066fc3677111ae04ea99f1e9ca2ee767bcae646b57cdc2b7e48c17ef68f6e1af856789a6d1d01cfe889401215e6e9f39d009e477541cc6aa774798a7a3b93c6dbc595e5b21acb9bfd3bd05a889a8cc9aad250af6dfccdeaf1179400764b72ac513d1f8453056f4f695af8d81b80ef06f94ca2a8cfea9cfe54ff9ef04fccaeb94b26bb5d743bf3f726a6c23422d57ff6920a3d398be7b144aed6fc8100b6e8cd2bf366c91b8a235952a667e568e40a01682c8c0b1bf9c99d4a0793b10970bbe6168cafd18edee9a65908b73fd29705ebaf9de8df2d98dfde30c09b1deb540b87c92d8427342da4eefa3397938185b5f814c819712655b9d582f6fc227c93466b3446ff479072fbc3b0021f765d0fce6f80212ae34b6d3d677abec6dddf40afdce5a1a61e55647d0af1840c29f68c658913abfc677c304161e0c8e64474b68346a5b9a65d4fe5129d21507b6195eaf58f535019b5
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147877);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2020-3437");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt65026");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanwebid-5QWMcCvt");

  script_name(english:"Cisco SD-WAN vManage Software Information Disclosure (cisco-sa-vmanwebid-5QWMcCvt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage software installed on the remote host is affected by an information disclosure
vulnerability as referenced in the cisco-sa-vmanwebid-5QWMcCvt advisory.

  - A vulnerability in the web-based management interface of Cisco SD-WAN vManage Software could allow an
    authenticated, remote attacker to read arbitrary files on the underlying filesystem of the device. The
    vulnerability is due to insufficient file scope limiting. An attacker could exploit this vulnerability by
    creating a specific file reference on the filesystem and then accessing it through the web-based
    management interface. A successful exploit could allow the attacker to read arbitrary files from the
    filesystem of the underlying operating system. (CVE-2020-3437)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanwebid-5QWMcCvt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e42b3a08");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt65026");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt65026");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3437");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
    {'min_ver': '0.0','fix_ver': '19.2.3.0'}
];

vuln_versions = [
  '19.2.097',
  '19.2.099'
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt65026',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:vuln_versions,
  reporting:reporting
);
