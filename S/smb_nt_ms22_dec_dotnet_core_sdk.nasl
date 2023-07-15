#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168827);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/16");

  script_cve_id("CVE-2022-41089");
  script_xref(name:"IAVA", value:"2022-A-0526");

  script_name(english:"Security Update for .NET Core SDK (December 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core SDK remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core SDK installation on the remote host is version affected by a remote code execution
vulnerability when parsing maliciously crafted xps files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/7.0");
  # https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.32/3.1.32.md?WT.mc_id=dotnet-35129-website#net-core-3132---december-13-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?834570c3");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.12/6.0.12.md?WT.mc_id=dotnet-35129-website#net-6012---december-13-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7e756e5");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.1/7.0.1.md?WT.mc_id=dotnet-35129-website#net-701----december-13-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14ac0d4c");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core SDK, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = '.NET Core SDK Windows';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '3.1',     'fixed_version' : '3.1.426' },
  { 'min_version' : '6.0',     'fixed_version' : '6.0.404' },
  { 'min_version' : '7.0',     'fixed_version' : '7.0.101' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
