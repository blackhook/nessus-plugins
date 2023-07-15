#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(166054);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id("CVE-2022-41032");
  script_xref(name:"MSKB", value:"5019349");
  script_xref(name:"MSKB", value:"5019351");
  script_xref(name:"MSFT", value:"MS22-5019349");
  script_xref(name:"MSFT", value:"MS22-5019351");
  script_xref(name:"IAVA", value:"2022-A-0411-S");

  script_name(english:"Security Updates for Microsoft .NET Core (October 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET core installations on the remote host are affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"A privilege escalation vulnerability exists in .NET core 6.0 < 6.0.10 and .NET Core 3.1 < 3.1.30. An authenticated,
local attacker can exploit this, via the NuGet client, to cause the user to execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5019349");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5019351");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  # https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.30/3.1.30.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a5250e3");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.10/6.0.10.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0eafd070");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/core/issues/7864");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core Runtime to version 3.1.30 or 6.0.10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin", "macosx_dotnet_core_installed.nbin");
  script_require_ports("installed_sw/.NET Core Windows", "installed_sw/.NET Core MacOS");

  exit(0);
}

include('vcf.inc');

var app;
var win_local;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
{
  app = '.NET Core Windows';
  win_local = TRUE;
}
else if (!empty_or_null(get_kb_item('Host/MacOSX/Version')))
{
  app = '.NET Core MacOS';
  win_local = FALSE;
}
else
  audit(AUDIT_HOST_NOT, 'Windows or macOS');

var app_info = vcf::get_app_info(app:app, win_local:win_local);
var constraints = [
  {'min_version': '3.1', 'fixed_version': '3.1.30'},
  {'min_version': '6.0', 'fixed_version': '6.0.10'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
