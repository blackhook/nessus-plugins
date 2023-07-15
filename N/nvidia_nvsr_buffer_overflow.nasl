#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63417);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_bugtraq_id(57123);
  script_xref(name:"EDB-ID", value:"24207");

  script_name(english:"NVIDIA Display Driver Service Remote Stack Buffer Overflow (credentialed check)");
  script_summary(english:"Checks Driver Version");

  script_set_attribute(attribute:"synopsis", value:
"A video display service on the remote Windows host is affected by a
stack-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Display Driver Service on the remote Windows host is
affected by a remote stack-based buffer overflow. An authenticated,
remote attacker, by connecting to the nsvr named pipe and making a
specially crafted request, could exploit this to execute arbitrary
code as SYSTEM.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/dailydave/2013/q1/6");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55026");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55121");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55217");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55220");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55599");
  script_set_attribute(attribute:"see_also", value:"http://www.nvidia.com/download/driverResults.aspx/56056");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA graphics drivers version 307.74 / 310.90 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Manual Analysis of the vulnerability");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nvidia (nvsvc) Display Driver Service Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:display_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");
  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '304.0', 'fixed_version': '307.74'},
  {'min_version': '310.0', 'fixed_version': '310.90'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
