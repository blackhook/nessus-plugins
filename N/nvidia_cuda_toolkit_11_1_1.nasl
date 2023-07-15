##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142492);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id("CVE-2020-5991");
  script_xref(name:"IAVB", value:"2020-B-0064-S");

  script_name(english:"NVIDIA CUDA Toolkit < 11.1.1 ( 11.1 Update 1 ) Arbitrary Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The version of NVIDIA CUDA Toolkit installed on the remote host is affected by an Arbitrary Code Execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"NVIDIA CUDA Toolkit contains a vulnerability in the NVJPEG library in which an out-of-bounds read or write operation 
may lead to code execution, denial of service, or information disclosure.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5094");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA CUDA Toolkit 11.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5991");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:cuda_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_cuda_toolkit_win_installed.nbin");
  script_require_keys("installed_sw/NVIDIA CUDA Toolkit");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'NVIDIA CUDA Toolkit');

constraints = [
  { 'fixed_version' : '11.1.105', 'fixed_display' : '11.1.105 (11.1 Update 1)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
