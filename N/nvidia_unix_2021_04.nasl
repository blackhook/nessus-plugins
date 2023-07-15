##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149046);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/11");

  script_cve_id("CVE-2021-1076", "CVE-2021-1077");
  script_xref(name:"IAVB", value:"2021-B-0027");

  script_name(english:"NVIDIA Linux GPU Display (April 2021)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Windows and Linux, all versions, contains a vulnerability in the kernel mode
    layer (nvlddmkm.sys or nvidia.ko) where improper access control may lead to denial of service, information 
    disclosure, or data corruption (CVE-2021-1076).

  - NVIDIA GPU Display Driver for Windows and Linux, R450 and R460 driver branch, contains a vulnerability 
    where the software uses a reference count to manage a resource that is incorrectly updated, which may lead
    to denial of service (CVE-2021-1077).

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5172
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?651e081d");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "NVIDIA_UNIX_Driver/GPU_Model", "Settings/ParanoidReport");

  exit(0);
}
include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'390', 'fixed_version':'390.143', 'gpumodel':['geforce', 'nvs', 'quadro']},
  {'min_version':'418', 'fixed_version':'418.197.02', 'gpumodel':'tesla'},
  {'min_version':'450', 'fixed_version':'450.119.03', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version':'460', 'fixed_version':'460.73.01', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version':'465', 'fixed_version':'465.24.02', 'gpumodel':['geforce', 'nvs', 'quadro']},
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
  
