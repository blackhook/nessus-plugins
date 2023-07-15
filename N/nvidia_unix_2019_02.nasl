#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122509);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2018-6260");
  script_xref(name:"IAVA", value:"2019-A-0063-S");

  script_name(english:"NVIDIA Linux GPU Display Driver Information Disclosure Vulnerability (CVE-2018-6260)");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing
a security update. It is, therefore, affected by a local information
disclosure vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4772");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor
advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6260");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'418', 'fixed_version':'418.43', 'gpumodel':['geforce', 'nvs','quadro']},
  {'min_version':'410', 'fixed_version':'410.104', 'gpumodel':['geforce', 'nvs','quadro']},
  {'min_version':'390', 'fixed_version':'390.116', 'gpumodel':['geforce', 'nvs','quadro']},
  {'min_version':'418', 'fixed_version':'418.39', 'gpumodel':'tesla'},
  {'min_version':'410', 'fixed_version':'410.104', 'gpumodel':'tesla'},
  {'min_version':'396', 'fixed_version':'396.82', 'gpumodel':'tesla'},
  {'min_version':'390', 'fixed_version':'390.116', 'gpumodel':'tesla'},
  {'min_version':'384', 'fixed_version':'384.183', 'gpumodel':'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);