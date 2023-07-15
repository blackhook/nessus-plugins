#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176108);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/22");

  script_cve_id("CVE-2023-20055");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd21514");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dnac-privesc-QFXe74RS");
  script_xref(name:"IAVA", value:"2023-A-0155");

  script_name(english:"Cisco DNA Center Privilege Escalation (cisco-sa-dnac-privesc-QFXe74RS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco DNA Center installed on the remote host is prior to 2.3.3.6 or is 2.3.4.x. It is, therefore,
affected by a privilege escalation vulnerability. Due to unintended exposure of sensitive information in the web-based
management interface, an authenticated remote attacker can inspect responses from the API to access the API with the
privileges of a higher-level user account.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dnac-privesc-QFXe74RS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10cded15");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd21514");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd21514");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20055");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:digital_network_architecture_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_dna_center_web_detect.nbin");
  script_require_keys("installed_sw/Cisco DNA Center");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Cisco DNA Center');

vcf::check_granularity(app_info:app_info, sig_segments:4);
var constraints = [
  {'fixed_version': '2.3.3.6'},
  {'min_version': '2.3.4', 'fixed_version': '2.3.5', 'fixed_display': 'See vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
