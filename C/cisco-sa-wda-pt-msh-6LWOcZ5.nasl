##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146594);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/25");

  script_cve_id("CVE-2021-1372");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv02342");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wda-pt-msh-6LWOcZ5");
  script_xref(name:"IAVA", value:"2021-A-0098");

  script_name(english:"Cisco Webex Meetings Desktop App and Webex Productivity Tools for Windows Shared Memory Information Disclosure (cisco-sa-wda-pt-msh-6LWOcZ5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in Cisco Webex Meetings Desktop App and Webex Productivity Tools for Windows could allow an authenticated,
local attacker to gain access to sensitive information on an affected system. This vulnerability is due to the unsafe
usage of shared memory by the affected software. An attacker with permissions to view system memory could exploit this
vulnerability by running an application on the local system that is designed to read shared memory. A successful exploit
could allow the attacker to retrieve sensitive information from the shared memory, including usernames, meeting
information, or authentication tokens. Note: To exploit this vulnerability, an attacker must have valid credentials on a
Microsoft Windows end-user system and must log in after another user has already authenticated with Webex on the same
end-user system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wda-pt-msh-6LWOcZ5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e77f276");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv02342");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv02342, CSCvv21029");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(202);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_meetings");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_meetings_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Webex Meetings", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Paranoid since we don't detect channels.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

get_kb_item_or_exit('Host/local_checks_enabled');
app = 'Cisco Webex Meetings';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

fixed_display = 'See vendor advisory';
constraints = [
  { 'fixed_version' : '40.10', 'fixed_display' : fixed_display }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);