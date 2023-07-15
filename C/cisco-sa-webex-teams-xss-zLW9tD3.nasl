##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142590);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_cve_id("CVE-2020-26067");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv40214");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-teams-xss-zLW9tD3");
  script_xref(name:"IAVA", value:"2020-A-0511");

  script_name(english:"Cisco Webex Teams Web Interface Cross-Site Scripting Vulnerability Vulnerability (cisco-sa-webex-teams-xss-zLW9tD3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-webex-teams-xss-zLW9tD3)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Teams is affected by a vulnerability. 
The vulnerability is due to improper validation of usernames. An attacker could exploit this vulnerability by creating an account that 
contains malicious HTML or script content and joining a space using the malicious account name. A successful exploit could allow the 
attacker to conduct cross-site scripting attacks and potentially gain access to sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-teams-xss-zLW9tD3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fd2bc19");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv40214");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv40214");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26067");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(80);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:webex_teams");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_teams_installed_win.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Webex Teams", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Webex Teams';

app_info = vcf::get_app_info(app:app, port:port, win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

# https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-teams-xss-zLW9tD3 
# does not show any version info (either in advisory, CVRF or bug ID)
# flagging anything under 99.9.9
constraints = [
    { 'fixed_version': '99.9.9', 'fixed_display': 'Consult Vendor Advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
