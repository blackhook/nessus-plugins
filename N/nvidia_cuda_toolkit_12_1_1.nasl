#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174902);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id("CVE-2023-25510", "CVE-2023-25511", "CVE-2023-25514");
  script_xref(name:"IAVB", value:"2023-B-0027");

  script_name(english:"NVIDIA CUDA Toolkit < 12.1 Update 1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of NVIDIA CUDA Toolkit installed on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA CUDA Toolkit installed on the remote host is prior to 12.1 Update 1. It is, therefore, affected
by multiple vulnerabilities:

  - NVIDIA CUDA toolkit for Linux and Windows contains a vulnerability in cuobjdump, where an attacker may
    cause an out-of-bounds read by tricking a user into running cuobjdump on a malformed input file. A
    successful exploit of this vulnerability may lead to limited denial of service, code execution, and
    limited information disclosure. (CVE-2023-25514)

  - NVIDIA CUDA Toolkit for Linux and Windows contains a vulnerability in cuobjdump, where a division-by-zero
    error may enable a user to cause a crash, which may lead to a limited denial of service. (CVE-2023-25511)

  - NVIDIA CUDA Toolkit SDK for Linux and Windows contains a NULL pointer dereference in cuobjdump, where a
    local user running the tool against a malformed binary may cause a limited denial of service.
    (CVE-2023-25510)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5456");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA CUDA Toolkit 12.1 Update 1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25514");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/27");

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

# fixed ver can be obtained via https://anaconda.org/nvidia/repo/files by clicking on the button for the version under
# cuda-nvcc, then looking at the file names under cuda-nvcc
var constraints = [
  { 'fixed_version' : '12.1.105', 'fixed_display' : '12.1 Update 1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
