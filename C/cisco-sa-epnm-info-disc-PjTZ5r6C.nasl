#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152540);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-34707");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs67013");
  script_xref(name:"CISCO-SA", value:"cisco-sa-epnm-info-disc-PjTZ5r6C");
  script_xref(name:"IAVA", value:"2021-A-0367-S");

  script_name(english:"Cisco Evolved Programmable Network Manager Information Disclosure (cisco-sa-epnm-info-disc-PjTZ5r6C)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in Cisco Evolved Programmable Network Manager. An authenticated, remote
attacker can exploit this, by sending a specific API request to the affected application, to disclose potentially sensitive
information about the application.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-epnm-info-disc-PjTZ5r6C
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42269343");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs67013");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs67013");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34707");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:evolved_programmable_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_epn_manager_detect.nbin");
  script_require_keys("installed_sw/Cisco EPN Manager");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'Cisco EPN Manager', webapp:TRUE, port:port);

var constraints = [
  { 'min_version': '0.0' ,'fixed_version' : '5.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
