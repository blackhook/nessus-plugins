#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138357);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2020-5963", "CVE-2020-5967");
  script_xref(name:"IAVA", value:"2020-A-0290-S");

  script_name(english:"NVIDIA Linux GPU Display (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - A code execution vulnerability exists in the Inter Process Communication APIs due to improper access 
    control. An authenticated, local attacker can exploit this issue to cause a denial of service condition,
    execute code or disclose potentially sensitive information. (CVE‑2020‑5963)
  
  - A denial of service vulnerability exists in the UVM driver due to a race condition. A local authenticated
    attacker could exploit this issued to cause a denial of service condition. (CVE‑2020‑5967)");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5031
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4702d9ab");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5963");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'450', 'fixed_version':'450.51', 'gpumodel':['geforce', 'nvs','quadro']},
  {'min_version':'440', 'fixed_version':'440.100', 'gpumodel':['geforce', 'nvs','quadro']},
  {'min_version':'390', 'fixed_version':'390.138', 'gpumodel':['geforce', 'nvs','quadro']},
  {'min_version':'450', 'fixed_version':'450.51.05', 'gpumodel':'tesla'},
  {'min_version':'440', 'fixed_version':'440.95.01', 'gpumodel':'tesla'},
  {'min_version':'418', 'fixed_version':'418.152.00', 'gpumodel':'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);