##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147946);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2021-26701");
  script_xref(name:"IAVA", value:"2021-A-0091-S");

  script_name(english:"Security Update for .NET Core (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core remote code execution (RCE) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core installation on the remote host is version 2.1.x prior to 2.1.26, 3.1.x prior to 3.1.13, or
5.x prior to 5.0.4. It is, therefore, affected by a remote code execution vulnerability. An unauthenticated, remote
attacker can exploit this to bypass authentication and execute arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/2.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/runtime/issues/49377");
  script_set_attribute(attribute:"see_also", value:"https://devblogs.microsoft.com/dotnet/net-march-2021/");
  # https://github.com/dotnet/core/blob/main/release-notes/2.1/2.1.26/2.1.26.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba8a76f7");
  # https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.13/3.1.13.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a16be048");
  # https://github.com/dotnet/core/blob/main/release-notes/5.0/5.0.4/5.0.4.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?414a18dd");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26701");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');

app = '.NET Core Windows';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '2.1',     'fixed_version' : '2.1.26' },
  { 'min_version' : '3.1',     'fixed_version' : '3.1.13' },
  { 'min_version' : '5.0',     'fixed_version' : '5.0.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
