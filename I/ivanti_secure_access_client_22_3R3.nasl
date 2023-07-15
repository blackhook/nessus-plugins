#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177586);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-34298");
  script_xref(name:"IAVA", value:"2023-A-0313");

  script_name(english:"Ivanti Secure Access Client < 22.3R3 Local Privilege Escalation (CVE-2023-34298)");

  script_set_attribute(attribute:"synopsis", value:
"A VPN client installed on the remote windows system is affected by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Ivanti Secure Access Client installed on the remote Windows system is prior to 22.3R3. It is, therefore,
affected by a local privilege escalation vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/CVE-2023-34298-Ivanti-Secure-Access-Client-local-privilege-escalation?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9cdeb59");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ivanti Secure Access Client version 22.3R3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34298");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ivanti:ivanti_secure_access_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("juniper_pulse_client_installed.nbin");
  script_require_keys("installed_sw/Ivanti Secure Access Client");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Ivanti Secure Access Client', win_local:TRUE);

var constraints = [
  {'min_version':'22.0.0', 'fixed_version':'22.3.3', 'fixed_display':'22.3R3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
