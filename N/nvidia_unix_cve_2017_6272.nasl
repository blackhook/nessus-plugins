#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103457);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2017-6266", "CVE-2017-6267", "CVE-2017-6272");

  script_name(english:"NVIDIA Linux GPU Display Driver 375.x < 375.88 / 384.x < 384.90 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"NVIDIA GPU display driver vulnerabilities may lead to denial of
service or possible escalation of privileges. To exploit these
vulnerabilities an attacker would send a malicious request to an
affected application or interact with an affected application. If
successfully exploited, these vulnerabilities would allow an
attacker to cause a denial of service condition or elevated
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4544");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 375.88 / 384.90 or later
in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'384', 'fixed_version':'384.90', 'gpumodel':['geforce', 'nvs','quadro']},
  {'min_version':'375', 'fixed_version':'375.88', 'gpumodel':'tesla'},
  {'min_version':'384', 'fixed_version':'384.81', 'gpumodel':'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);