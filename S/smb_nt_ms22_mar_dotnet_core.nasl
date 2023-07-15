#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158744);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/18");

  script_cve_id("CVE-2020-8927", "CVE-2022-24464", "CVE-2022-24512");
  script_xref(name:"IAVA", value:"2022-A-0106-S");

  script_name(english:"Security Updates for Microsoft .NET core (March 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET core installations on the remote host are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET core installations on the remote host are missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected
    component to deny system or application services. (CVE-2022-24464)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2020-8927, CVE-2022-24512)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/210");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-8927
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56caba70");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-24464
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95177a8e");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-24512
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96c2a71d");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core Runtime to version 3.1.23, 5.0.15 or 6.0.3.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24512");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8927");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
else if (!empty_or_null(get_kb_item("Host/MacOSX/Version")))
{
  app = '.NET Core MacOS';
  win_local = FALSE;
}
else
  audit(AUDIT_HOST_NOT, 'Windows or macOS');

var app_info = vcf::get_app_info(app:app, win_local:win_local);
var constraints = [
  {'min_version': '3.1', 'fixed_version': '3.1.23'},
  {'min_version': '5.0', 'fixed_version': '5.0.15'},
  {'min_version': '6.0', 'fixed_version': '6.0.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
