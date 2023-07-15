#TRUSTED 18536e7bdc0dd4975e2a6fecc900b974dd7b5d5cba7d1b5d841629c63408676406ce487a5a2e0508f524e782aba94418e3875f8f8b16ca346aac4129e33a27cd1c674d8f96a2821604af8dfc390ca28e8dddd269a7722e89a395c06dcab2a82267975e48023204a4cf9961f30ebc907bd0bcbef8e2f978c9f5f0dc09bfaf467b35dcf9e2f937aab4f4dfc6f6179345df3bab41a3d7fd287938656a3d0fa3a06e755df8731e58dd4899bed5851aec301de8f58c336f667b68921a51a59c41b76255094d91c7c209c6b31dddf5264122033dd1e612aeda463992e6f0f2a732df483593fe5611957b59e35ec9d6d2b4034e70fa35fd87c9a85ce50efa65220aaa3eb2a7b11b5e16da230392441b6faf7960c0d7887c9a5140c6ad88e6f5a6faaae58c3f43d42a9255ad18aabbf7d8fccb455f733041458ec5d0bde36f215bf19088c412a0d43c273cecb3e21e91c1cdcff7527ba07c4f66040e31cb4850b5d65524a6cc3b941806a0370c69fdd7e8cc13eba6b3500570a895c01d9f46892cb4567af6e8aebe89c98193a66e9f73e50d763ec8f64bba43c5b30dceb45d822967942ec990764dffead7a320c26c32ee1b0242476c06a37e50f45827f4466b989fe2b6e9aa31c351076b42a8d44dbbaa6331452a6872a4e2da90c11ce44b36fa982f3623db7d298e1d19bce8ae87735f3d2e10bae136a36e2bf886b9d4f4d0425bfd38
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142597);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_cve_id("CVE-2020-3591");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv42620");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanxsshi-9KHEqRpM");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage XSS (cisco-sa-vmanxsshi-9KHEqRpM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a cross-site scripting (XSS) vulnerability
in the web-based management interface due to not properly validating user-supplied input. An authenticated, remote
attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a
user's browser session.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanxsshi-9KHEqRpM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3eb25407");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv42620");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv42620");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3591");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'20.1.0', 'fix_ver':'20.1.2' }
];

version_list=make_list(
  '20.1.12',
  '20.3.1'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv42620',
  'fix'      , 'See vendor advisory',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
