#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83521);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id("CVE-2013-0109", "CVE-2013-0110", "CVE-2013-0111");
  script_bugtraq_id(58459, 58460, 58461);
  script_xref(name:"CERT", value:"957036");
  script_xref(name:"EDB-ID", value:"30393");

  script_name(english:"NVIDIA Display Driver 174.x < 307.78 / 310.x < 311.00 Multiple Vulnerabilities");
  script_summary(english:"Checks Driver Version");

  script_set_attribute(attribute:"synopsis", value:
"A video display service on the remote Windows host is affected by
multiple privilege escalation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA Display Driver service on the remote Windows
host is later than 174.00 but prior to 307.78, or later than 310.00
but prior to 311.00. It is therefore affected by the following
vulnerabilities :

  - An privilege escalation vulnerability exists due to not
    properly handling exceptions. A local attacker, using a
    crafted application, could exploit this to overwrite
    memory, allowing the execution of arbitrary code or
    causing a denial of service. (CVE-2013-0109)

  - A privilege escalation vulnerability exists in the
    Stereoscopic 3D Driver service due to an unquoted
    service search path. A local attacker, using a trojan
    horse program, could exploit this to execute arbitrary
    code in the root path. (CVE-2013-0110)

  - A privilege escalation vulnerability exists in the
    Update Service Daemon due to an unquoted service search
    path. A local attacker, using a trojan horse program,
    could exploit this to execute arbitrary code in the root
    path. (CVE-2013-0111)");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3288");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA graphics drivers version 307.78 / 311.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0109");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nvidia (nvsvc) Display Driver Service Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:display_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");
  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '174.0', 'fixed_version': '307.78'},
  {'min_version': '310.0', 'fixed_version': '311.00'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
