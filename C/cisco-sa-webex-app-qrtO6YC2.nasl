#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164904);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20863");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb85392");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-app-qrtO6YC2");
  script_xref(name:"IAVA", value:"2022-A-0353");

  script_name(english:"Cisco Webex Meetings App Character Interface Manipulation (cisco-sa-webex-app-qrtO6YC2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a App Character Interface Manipulation vulnerability.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the messaging interface of Cisco Webex App, formerly Webex Teams, could allow an unauthenticated,
remote attacker to manipulate links or other content within the messaging interface. This vulnerability exists because
the affected software does not properly handle character rendering. An attacker could exploit this vulnerability by
sending messages within the application interface. A successful exploit could allow the attacker to modify the display
of links or other content within the interface, potentially allowing the attacker to conduct phishing or spoofing
attacks.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-app-qrtO6YC2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0db60f7f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb85392");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20863");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:webex_app");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_app_installed.nbin");
  script_require_keys("installed_sw/Webex App");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Webex App');

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '42.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
