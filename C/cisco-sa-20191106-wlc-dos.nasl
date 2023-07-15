#TRUSTED 412a69bbd50fe1e910d6dc37f7011760567f68011d7ac63ba2fa67d69ae7b1c7fdf172a98ca13b286185e547d9f8af94d267057e32f48caeb2955d2a3aba1d2e56807284c939c9105d9fa25aa489dd36810ca3396f15fbcd8255e534d1f43a1122792aa3b48aac0850a1399bfd76fbe9f4cf947008d1ba0433a8c3a1990c5b0157b32585e39460feee5aabdc059df77b91f7952b376139358e2d49e54b2fd30abe1056ccc0d162e6dcb6a374f0342fd7a4ab52ba4a82ab771caac6f1661b2f836a5970fdc4d282dc0123bdfe79399989325f8ef4d9f6ebba63f06c3d03bf77ea1e7cbdd1c02ed3edf861655acce716254d031ba812a2ebd944344be963a44b31f46de22b24b6d2c3afd097c0bb038601ea94bf109645c04b24daadfb7b6cde249e8629b01dfc86c1591007417e5c0a178af6530d79c51f68de542377b109ca4fb1ec4640d3eaec231974ac278aea5e11b3c37e6bc551a38c9b42493f0ff8cc621a5a46353b3ecdf88b4dec528fbfc8ea479cc898caeeb640d981615412f0a58dd8da6b740c5d0c2124b8f756a0028410b9d75d28084ce032dc74d6fc96ee133025fcd980ed9c22723e38485a0d0a308212156a7696106b27058006d06f8b052b57463a841fafe35c3f161f7b7646e486f464efb937f37d49b7ed4c95ae734f890e8fcc9c23754ed124f94a44481652a9b659ae878ee4996556bbb9f64165ec9a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131230);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2019-15276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp92098");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191106-wlc-dos");
  script_xref(name:"IAVA", value:"2019-A-0424");

  script_name(english:"Cisco Wireless LAN Controller HTTP Parsing Engine Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco Wireless Lan Controller due to a HTTP Parsing Engine Vulnerability.
An unauthenticated, remote attacker can exploit this issue, via a HTTP request, to cause the device to stop responding.
Please see the included Cisco Bug IDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191106-wlc-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f68b41a");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp92098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eafb222d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version for your machine as referenced in Cisco bug ID CSCvp92098");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15276");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [ # 8.8 will get Maintainence Version in the future.
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.160.0'},
  { 'min_ver' : '8.6', 'fix_ver' : '8.10'}
];

reporting = make_array(
    'port'            , product_info['port'],
    'disable_caveat'  , TRUE,
    'severity'        , SECURITY_WARNING,
    'version'         , product_info['version'],
    'bug_id'          , 'CSCvp92098'
);

cisco::check_and_report(
    product_info:product_info,  
    reporting:reporting, 
    vuln_ranges:vuln_ranges);
