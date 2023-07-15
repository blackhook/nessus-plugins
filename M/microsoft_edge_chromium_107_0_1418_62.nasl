#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168239);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-4135");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/12/19");
  script_xref(name:"IAVA", value:"2022-A-0501-S");
  script_xref(name:"IAVA", value:"2022-A-0502-S");

  script_name(english:"Microsoft Edge (Chromium) < 107.0.1418.62 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 107.0.1418.62. It is, therefore, affected
by a vulnerability as referenced in the November 28, 2022 advisory.

  - Heap buffer overflow in GPU in Google Chrome prior to 107.0.5304.121 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (Chromium security severity: High) (CVE-2022-4135)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#november-28-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fa4911e");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4135");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 107.0.1418.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4135");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '107.0.1418.62' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
