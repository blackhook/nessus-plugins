#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102783);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2017-6251",
    "CVE-2017-6252",
    "CVE-2017-6253",
    "CVE-2017-6254",
    "CVE-2017-6255",
    "CVE-2017-6256",
    "CVE-2017-6257",
    "CVE-2017-6259",
    "CVE-2017-6260"
  );

  script_name(english:"NVIDIA Windows GPU Display Driver 375.x < 377.55 / 384.x < 384.94 / 385.x < 385.08 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Nvidia GPU Display driver vulnerabilities may lead to denial of 
service or possible escalation of Privileges. To exploit these 
vulnerabilities an attacker would send a malicious request to an 
affected application or interact with an affected application. If 
successfully exploited, these vulnerabilities would allow an 
attacker to cause a denial of service condition or elevated 
privileges.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/4525
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3f0ec60");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 377.55 / 384.94 / 385.08 or
later in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6251");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '375.0', 'fixed_version': '377.55'},
  {'min_version': '385.0', 'fixed_version': '385.08'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
