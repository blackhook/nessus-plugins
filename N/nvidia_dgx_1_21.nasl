#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178027);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-25521", "CVE-2023-25522");
  script_xref(name:"IAVB", value:"2023-B-0047");

  script_name(english:"NVIDIA DGX A100/A800 System BIOS < 1.21 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The System BIOS on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The system BIOS on the remote NVIDIA DGX A100 or A800 system is prior to 1.21. It is, therefore, affected by the
following vulnerabilities:

  - Improper validation of an input parameter can lead to code execution, escalation of privileges, denial
    of service, information disclosure and data tampering. (CVE-2023-25521)

  - Information provided in an unexpected format can cause improper validation of an input parameter
    leading to denial of service, information disclosure and data tampering (CVE-2023-25522)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5461");
  script_set_attribute(attribute:"solution", value:
"Upgrade the System BIOS in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25522");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-25521");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:nvidia:dgx_a100");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:nvidia:dgx_a800");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dmi_system_info.nasl", "bios_get_info_ssh.nasl");
  script_require_keys("BIOS/Version", "DMI/System/SystemInformation/Manufacturer", "DMI/System/SystemInformation/ProductName");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_dgx_a100_sbios::get_app_info();

var constraints = [
  {'fixed_version': '1.21'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


