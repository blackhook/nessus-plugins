#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82528);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id("CVE-2015-1170");
  script_bugtraq_id(73442);

  script_name(english:"NVIDIA Graphics Driver Local Privilege Escalation");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privileges escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a driver installed this is affected by a
privilege escalation vulnerability due to a failure to properly
validate local client impersonation levels when performing a kernel
administrator check. A local attacker can exploit this issue, via 
unspecified API calls, to gain administrator privileges.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3634");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate video driver version per the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1170");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/02/23");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/02");
  
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
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
  {'min_version': '304.0', 'fixed_version': '309.08'},
  {'min_version': '340.0', 'fixed_version': '341.44'},
  {'min_version': '343.0', 'fixed_version': '345.20'},
  {'min_version': '346.0', 'fixed_version': '347.52'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
