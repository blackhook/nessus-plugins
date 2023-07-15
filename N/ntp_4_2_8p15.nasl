#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138356);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2020-15025");
  script_xref(name:"IAVA", value:"2020-A-0289");

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.8p15 / 4.3.x < 4.3.101 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.8p15, or is 4.3.x prior to 4.3.101. It is, therefore, affected
by a denial of service vulnerability due to a flaw in handling unauthenticated synchronization traffic. An authenticated
attacker can exploit this issue to cause denial of service.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.ntp.org/bin/view/Main/NtpBug3661");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p15, 4.3.101 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("NTP/Running", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

# Paranoia check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::ntp::get_app_info();

constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '4.2.8.15', 'fixed_display' : '4.2.8p15' },
  { 'min_version' : '4.3', 'fixed_version' : '4.3.101' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
