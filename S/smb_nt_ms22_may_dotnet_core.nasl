#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(161167);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/04");

  script_cve_id("CVE-2022-23267", "CVE-2022-29117", "CVE-2022-29145");
  script_xref(name:"IAVA", value:"2022-A-0201-S");

  script_name(english:"Security Updates for Microsoft .NET core (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET core installations on the remote host are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET core installations on the remote host are missing security updates. It is, therefore, affected by
multiple denial of service vulnerabilities:

  - A vulnerability where a malicious client can cause a denial of service via excess memory allocations
    through HttpClient. (CVE-2022-23267)

  - A vulnerability where a malicious client can manipulate cookies and cause a denial of service. (CVE-2022-29117)

  - A vulnerability where a malicious client can cause a denial of service when HTML forms are parsed. (CVE-2022-29145)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/219");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-23267
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b99f604");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-29117
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1b0aff4");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-29145
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39d07c32");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core Runtime to version 3.1.25, 5.0.17 or 6.0.5.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23267");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-29145");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

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
else if (!empty_or_null(get_kb_item("Host/MacOSX/Version")))
{
  app = '.NET Core MacOS';
  win_local = FALSE;
}
else
  audit(AUDIT_HOST_NOT, 'Windows or macOS');

var app_info = vcf::get_app_info(app:app, win_local:win_local);
var constraints = [
  {'min_version': '3.1', 'fixed_version': '3.1.25'},
  {'min_version': '5.0', 'fixed_version': '5.0.17'},
  {'min_version': '6.0', 'fixed_version': '6.0.5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
