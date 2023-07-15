##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142503);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2020-3588");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv52829");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-vdi-qQrpBwuJ");
  script_xref(name:"IAVA", value:"2020-A-0501");

  script_name(english:"Cisco Webex Meetings Desktop App Arbitrary Code Execution Vulnerability (cisco-sa-webex-vdi-qQrpBwuJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Meetings Desktop
App is prior to version 40.6.9, or is 40.8.x prior to 40.8.9 and thus,
is affected by a remote code execution vulnerability. An unspecified
flaw exists related to the virtualization channel interface that can
allow a local attacker to execute arbitrary code with elevated
privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-vdi-qQrpBwuJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?312c4533");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv52829");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 40.6.9, 40.8.9, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3588");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_meetings");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_meetings_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Webex Meetings", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# We do not know if HVD is involved.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit('installed_sw/Cisco Webex Meetings');
app = 'Cisco Webex Meetings';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'fixed_version' : '40.6.9' },
  { 'min_version' : '40.8.0', 'fixed_version' : '40.8.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
