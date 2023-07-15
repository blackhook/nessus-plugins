#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172401);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");

  script_cve_id("CVE-2023-0193", "CVE-2023-0196", "CVE-2023-25512");
  script_xref(name:"IAVB", value:"2023-B-0027");
  script_xref(name:"IAVB", value:"2023-B-0014-S");

  script_name(english:"NVIDIA CUDA Toolkit < 12.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of NVIDIA CUDA Toolkit installed on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA CUDA Toolkit installed on the remote host is < 12.1. It is, therefore, affected by multiple
vulnerabilities:

  - NVIDIA CUDA Toolkit SDK contains a vulnerability in cuobjdump, where a local user running the tool against a 
    malicious binary may cause an out-of-bounds read, which may result in a limited denial of service and limited 
    information disclosure. (CVE-2023-0193)
  
  - NVIDIA CUDA Toolkit SDK contains a bug in cuobjdump, where a local user running the tool against an ill-formed 
    binary may cause a null- pointer dereference, which may result in a limited denial of service. (CVE-2023-0196)

  - NVIDIA CUDA toolkit for Linux and Windows contains a vulnerability in cuobjdump, where an attacker may cause an
    out-of-bounds memory read by running cuobjdump on a malformed input file. A successful exploit of this vulnerability
    may lead to limited denial of service, code execution, and limited information disclosure. (CVE-2023-25512)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5446/~/security-bulletin%3A-nvidia-cuda-toolkit---march-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d92fb5be");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5456");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA CUDA Toolkit 12.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25512");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:cuda_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_cuda_toolkit_win_installed.nbin");
  script_require_keys("installed_sw/NVIDIA CUDA Toolkit");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA CUDA Toolkit');

var constraints = [
  { 'fixed_version' : '12.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
