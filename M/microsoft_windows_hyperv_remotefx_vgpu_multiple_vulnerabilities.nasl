##
# (C) Tenable Inc.
##

include('compat.inc');

if (description)
{
  script_id(162570);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-1032",
    "CVE-2020-1036",
    "CVE-2020-1040",
    "CVE-2020-1041",
    "CVE-2020-1042",
    "CVE-2020-1043",
    "CVE-2020-6100",
    "CVE-2020-6101",
    "CVE-2020-6102",
    "CVE-2020-6103"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Microsoft Windows HyperV RemoteFX vGPU Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The Microsoft HyperV RemoteFX vGPU enabled on the remote host is affected by multiple vulnerabilities, including the following:

  - An exploitable code execution vulnerability exists in the Shader functionality. An attacker can provide a
    specially crafted shader file to trigger this vulnerability, resulting in code execution. This
    vulnerability can be triggered from a HYPER-V guest using the RemoteFX feature, leading to executing the
    vulnerable code on the HYPER-V host (inside of the rdvgm.exe process). Theoretically this vulnerability
    could be also triggered from web browser (using webGL and webassembly). (CVE-2020-6103, CVE-2020-6102)

  - An exploitable code execution vulnerability exists in the Shader functionality. An attacker can provide a
    specially crafted shader file to trigger this vulnerability, resulting in code execution. This
    vulnerability can be triggered from a HYPER-V guest using the RemoteFX feature, leading to executing the
    vulnerable code on the HYPER-V host (inside of the rdvgm.exe process). Theoretically this vulnerability
    could be also triggered from web browser (using webGL and webassembly). (CVE-2020-6101)

  - Remote code execution vulnerabilities exist when Hyper-V RemoteFX vGPU on a host server fails to properly
    validate input from an authenticated user on a guest operating system, aka 'Hyper-V RemoteFX vGPU Remote
    Code Execution Vulnerability'. (CVE-2020-1032, CVE-2020-1036, CVE-2020-1040, CVE-2020-1041, CVE-2020-1043,
    CVE-2020-1043)

Note that Nessus has not tested for this issue but has instead relied only on the application's presence on the machine.");
  # https://blog.talosintelligence.com/2020/07/vuln-spotlight-intel-amd-microsoft-july-2020.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5faeb054");
  # https://support.microsoft.com/en-us/topic/kb4570006-update-to-disable-and-remove-the-remotefx-vgpu-component-in-windows-bbdf1531-7188-2bf4-0de6-641de79f09d2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5507394");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1043");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6103");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:hyperv_remotefx_vgpu");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_windows_hyperv_remotefx_vgpu_detect.nbin");
  script_require_keys("installed_sw/Microsoft HyperV RemoteFX vGPU");

  exit(0);
}

include('vcf.inc');
include('smb_func.inc');

var app_info = vcf::get_app_info(app:'Microsoft HyperV RemoteFX vGPU', win_local:TRUE);

if (app_info['RemoteFX vGPU'] == 'Active')
{
  var report = 'Microsoft HyperV RemoteFX vGPU is active.';
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:kb_smb_transport());
}
else
  audit(AUDIT_OS_CONF_NOT_VULN, 'Windows');
