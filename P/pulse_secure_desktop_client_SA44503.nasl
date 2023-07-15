#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137857);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/30");

  script_cve_id("CVE-2020-13162");
  script_xref(name:"IAVA", value:"2020-A-0277-S");

  script_name(english:"Pulse Secure Desktop Client TOCTOU Privilege Escalation Vulnerability (SA44503)");

  script_set_attribute(attribute:"synopsis", value:
"A VPN client installed on the remote windows system is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Pulse Secure Desktop Client installed on the remote Windows system is affected by a TOCTOU (time-of-check to
time-of-use) privilege escalation vulnerability.");
  # https://www.redtimmy.com/privilege-escalation/pulse-secure-client-for-windows-9-1-6-toctou-privilege-escalation-cve-2020-13162/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cde3544f");
  script_set_attribute(attribute:"see_also", value:"https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44503");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Secure Desktop Client 9.1R6 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13162");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_secure_desktop_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("juniper_pulse_client_installed.nbin");
  script_require_keys("installed_sw/Pulse Secure Desktop Client");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Pulse Secure Desktop Client', win_local:TRUE);

constraints = [
  # 9.1R5 or below
  # 9.0RX
  {'min_version':'9.0.0', 'fixed_version':'9.1.6', 'fixed_display':'9.1R6'},
  # 5.3RX
  {'min_version':'5.3.0', 'max_version':'5.3.99', 'fixed_version':'9.1.6', 'fixed_display':'9.1R6'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

