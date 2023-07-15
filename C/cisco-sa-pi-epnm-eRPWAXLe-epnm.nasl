#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173977);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/28");

  script_cve_id("CVE-2023-20129", "CVE-2023-20130", "CVE-2023-20131");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc25461");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc51948");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc76734");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd28312");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd69561");
  script_xref(name:"CISCO-SA", value:"cisco-sa-pi-epnm-eRPWAXLe");
  script_xref(name:"IAVA", value:"2023-A-0219");

  script_name(english:"Cisco Evolved Programmable Network Manager Multiple Vulnerabilities (cisco-sa-pi-epnm-eRPWAXLe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Evolved Programmable Network (EPN) Manager installed on the remote host is prior to 5.0.2.5,
5.1.4.3, 6.0.2.1 or 6.1.1.1. It is, therefore, affected by multiple vulnerabilities as referenced in the
cisco-sa-pi-epnm-eRPWAXLe advisory:

  - A cross-site scripting (XSS) vulnerability in the web-based management interface of Cisco EPN Manager
    due insufficient validation user-supplied input. An authenticated, remote attacker can exploit this
    vulnerability to inject malicious code into specific pages of the interface allowing the attacker to
    execute arbitrary code in the context of the affected device or access sensitive, browser-based
    information. (CVE-2023-20131)

  - An arbitrary file read vulnerability in the web-based management interface of EPN Manager due to
    insufficient validation of user input. A remote, authenticated attacker can exploit this vulnerability to
    access sensitive files in the underlying operating system of the affected device. (CVE-2023-2023-20129)

  - A cross-site request forgery (CSRF) vulnerability in the web-based management interface of Cisco EPN
    Manager due to insufficient CSRF protections. An attacker could exploit this vulnerability by persuading a
    user of the interface to the follow a specially crafted link resulting in the attacker being able to
    perform arbitrary actions on the affected system with the privileges of the target user. (CVE-2023-20130)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pi-epnm-eRPWAXLe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?838ad81a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc25461");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc51948");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc76734");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd28312");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd69561");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwc25461, CSCwc51948, CSCwc76734, CSCwd28312,
CSCwd69561");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20130");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:evolved_programmable_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_epn_manager_detect.nbin");
  script_require_keys("installed_sw/Cisco EPN Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Cisco EPN Manager');

vcf::check_granularity(app_info:app_info, sig_segments:4);
var constraints = [
  {'min_version': '5.0', 'fixed_version': '5.0.2.5'},
  {'min_version': '5.1', 'fixed_version': '5.1.4.3'},
  {'min_version': '6.0', 'fixed_version': '6.0.2.1'},
  {'min_version': '6.1', 'fixed_version': '6.1.1.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{'xsrf':TRUE, 'xss':TRUE});
