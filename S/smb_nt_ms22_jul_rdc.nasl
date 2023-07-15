##
# Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163073);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id("CVE-2022-30221");
  script_xref(name:"IAVA", value:"2022-A-0273-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Remote Desktop Client for Windows RCE (July 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows Remote Desktop client for Windows installed on the remote host is missing security updates. It is, 
therefore, affected by a remote code execution vulnerability in the Windows Graphics component. An attacker can exploit
this to bypass authentication and execute unauthorized arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30221
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dfc3007");
  # https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/windowsdesktop-whatsnew#updates-for-version-123317
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b1f8019");
  script_set_attribute(attribute:"solution", value:
"Upgrade to client version 1.2.3317 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("remote_desktop_installed.nbin");
  script_require_keys("installed_sw/Microsoft Remote Desktop");

  exit(0);
}

include('vcf.inc');

var appname = "Microsoft Remote Desktop";

var app_info = vcf::get_app_info(app:appname, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    { 'fixed_version' : '1.2.3317' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
