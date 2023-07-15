#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158893);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/15");

  script_cve_id("CVE-2022-21816");
  script_xref(name:"IAVA", value:"2022-A-0102");

  script_name(english:"NVIDIA Linux vGPU Display Driver (February 2022)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA vGPU display driver software on the remote host is missing a security update. It is, therefore, affected by
a vulnerability:

  - NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (nvidia.ko), where a user in the guest OS
    can cause a GPU interrupt storm on the hypervisor host, leading to a denial of service. (CVE-2022-21816)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5312");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:virtual_gpu_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_vgpu_manager_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Virtual GPU Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Virtual GPU Manager');

var constraints = [
  {'min_version':'450.156', 'fixed_version':'450.172'},
  {'min_version':'470.82', 'fixed_version':'470.103.02'},
  {'min_version':'418.226.00', 'fixed_version':'418.240'},
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
  
