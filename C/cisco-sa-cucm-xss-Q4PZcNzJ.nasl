#TRUSTED 2281064a25e959fd6d3e9ac4ea99454ddc0f76d8f267a8fa2cc6ddf97b7c43d82f432d5c7d7346d32c707a1eead915c2d659f381af2abe35b4004c2798810cf36f97b9898bc20c9a663de091af85ba3cdc25653068a5b2b6755c11da6a68c676802e590ae52612319b21461790f4dd666a5e8391ca0ab4bfc5e7be8d2056e89e3839491e5414087e027c879f2638874d682b93d99129090ec9f9ae76a982cb3766540938613b81019de5ecdfa454147f10c791abb1126592d5cec37c10b3cdcefac8278f75b911d11785f35092e836dc6320fe3ddcb032251e6a619e150ee1bb1d7fb73e5a9806f5e90ab6f5dd5ddd74811a12ac04048cad2ba921881e0f11a988bd6bec941c0333660ed2438a02714e6c55375f7ade0b1be4290d618473d7b0711e376af64dc9e850f74b77b603338bfd1a4271bf458320e98a18acf3973ef49a57da14d1f5cbd265e16ee3b23ca8f5b5ec95a09dcf9326e1030ae4a846a8e5e58d57333e904b9e9106ebcb8fab134045f415494f2652ad0f5beb261c37102ad4ae6393a824199696d63b3dedf32b354e7db0206665cc815e2ac1256916db04f724d6ae39a0ab7da2588e1e55652dd1d44cfd9e5b6617da9fb2cbd484f0ab6e862af05fa354eb170cc070b9c81121d71ca00d68b61541314be455ed13e9d49c9cc36498d62f25d185f4f6fa96e9924b7d0493d0316cd45fa16782a6ffb75110
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149468);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-1380",
    "CVE-2021-1407",
    "CVE-2021-1408",
    "CVE-2021-1409"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu52262");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21040");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv28764");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv35159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw71918");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx14158");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx14178");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-xss-Q4PZcNzJ");
  script_xref(name:"IAVA", value:"2021-A-0162");

  script_name(english:"Cisco Unified Communications Manager XSS (cisco-sa-cucm-xss-Q4PZcNzJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of cisco unified communications manager installed on the remote host is prior to version 14. It is,
therefore, affected by multiple cross-site scripting vulnerabilities.

Multiple vulnerabilities in the web-based management interface of Cisco Unified CM, could allow an unauthenticated, remote
attacker to conduct an XSS attack against an interface user. An attacker could exploit this vulnerability by persuading
an interface user to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script
code in the context of the affected interface or access sensitive browser-based information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-xss-Q4PZcNzJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e61edeb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu52262");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21040");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv28764");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv35159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw71918");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx14158");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx14178");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu52262, CSCvv21040, CSCvv28764, CSCvv35159,
CSCvw71918, CSCvx14158, CSCvx14178");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1380");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# https://software.cisco.com/download/home/286328117/type/286319236/release/14
var vuln_ranges = [{'min_ver' : '0.0',  'fix_ver' : '14.0.1.10000.20'}];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvu52262, CSCvv21040, CSCvv28764, CSCvv35159, CSCvw71918, CSCvx14158, CSCvx14178',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
product_info:product_info, 
reporting:reporting, 
vuln_ranges:vuln_ranges
);