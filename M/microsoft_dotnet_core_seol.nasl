#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172179);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_name(english:"Microsoft .NET Core SEoL");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Microsoft .NET Core is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Microsoft .NET Core installed on the remote host is no longer maintained by its vendor or
provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  # https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89faa62b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft .NET Core that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin", "macosx_dotnet_core_installed.nbin");
  script_require_ports("installed_sw/.NET Core Windows", "installed_sw/.NET Core MacOS");

  exit(0);
}

include('ucf.inc');

var app;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  app = '.NET Core Windows';
else if (!empty_or_null(get_kb_item('Host/MacOSX/Version')))
  app = '.NET Core MacOS';
else
  audit(AUDIT_HOST_NOT, 'Windows or macOS');

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  {branch:'1.0', seol:20190627},
  {branch:'1.1', seol:20190627},
  {branch:'2.0', seol:20181001},
  {branch:'2.1', seol:20210821},
  {branch:'2.2', seol:20191223},
  {branch:'3.0', seol:20200303},
  {branch:'3.1', seol:20221213},
  {branch:'5.0', seol:20220510},
  {branch:'6.0', seol:20241112},
  {branch:'7.0', seol:20240514}
];


ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
