#TRUSTED 540b05958b37d8b733256ad4b6643d3d8bbeb8098ddcf18a452aa1b439e32b1df7ac896c80bb82e6dc23730ca4a07e5dba4dcd8e3bf8ef149e5adfcb3d2238c3dd3da0f86d4ae2df25d35c45789fda630005445f4462868f615e6f662aa10a3e125782ad73e61603566b17cdbbda8f11ee41f8dfed5d65d01e0630f66417b643684cad872b5de5476899a5be067b2178fecd2683019c3e90bdf011b1930f02ca86a3d1888c626a3195a83bdf7ee7ddf3c58e63ba7cf6949bbbed0921c3c379b7aa3e6d01086ec75b329773fa70ca09b51f9e787c94c4a78a9736885a074fa094b862e30687d5ebbc4f35dfd5813cddd4972f369c1a937f707de8889b45494a06e20a47a6ef30e507b4a535440676f5d6459fa43fe2731427847a4223e10db09a3aa57436084a36d2b2e9d7136e514bc879d4f3a66e51728b6ae10899680c332d6161102c48e9741b983e120015ae66fd4768c02f0d0c5c7ed36006f7223e9416211a8a9a25e2397dc2f591241342b82e102309a6647407b8400c314bb43e711c1574862fef6a4d77c29c325ea35a5833826dbb9606ad860ad54773703558e3d42b3dba79ff23fc359f9db71e78a3bcd8856c7738ead0340bfb60ac087ccea821c99e5f55ab17d76be99c4f40bcd964590434962a98ad71118be31f0853c69b7552514b3b9adc60ff5f42565108c96d83a047001afc7d97649cfa766fcd3ddf06
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155315);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/15");

  script_cve_id("CVE-2021-34753", "CVE-2021-34754");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy02240");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-enip-bypass-eFsxd8KP");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Firepower Threat Defense Software Ethernet Industrial Protocol Policy Bypass (cisco-sa-ftd-enip-bypass-eFsxd8KP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by multiple policy bypass vulnerabilities in 
its payload inspection component for Ethernet Industrial Protocol (ENIP) traffic due to incomplete deep packet 
inspection for ENIP traffic. An unauthenticated, remote attacker can exploit these, by sending specially crafted ENIP 
packets, to bypass configured access control and intrusion policies.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-enip-bypass-eFsxd8KP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b6bd38b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy02240");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy02240");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34754");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.1'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.3'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy02240',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
