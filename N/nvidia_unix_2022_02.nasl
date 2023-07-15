#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158894);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/15");

  script_cve_id("CVE-2022-21813", "CVE-2022-21814");
  script_xref(name:"IAVA", value:"2022-A-0102");

  script_name(english:"NVIDIA Linux GPU Display Driver (February 2022)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel driver, where improper handling of
    insufficient permissions or privileges may allow an unprivileged local user limited write access to protected
    memory, which can lead to denial of service. (CVE-2022-21813)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel driver package, where improper handling
    of insufficient permissions or privileges may allow an unprivileged local user limited write access to protected
    memory, which can lead to denial of service. (CVE-2022-21814)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5312");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "NVIDIA_UNIX_Driver/GPU_Model", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'470', 'fixed_version':'470.103.01', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version':'510', 'fixed_version':'510.47.03', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_NOTE
);
  
