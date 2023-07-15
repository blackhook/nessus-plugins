#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149472);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2021-31204");
  script_xref(name:"IAVA", value:"2021-A-0218-S");

  script_name(english:"Security Update for .NET Core (May 2021) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS host is affected by a .NET Core privilege elevation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core installation on the remote host is version 3.1.x prior to 3.1.15 or 5.x prior to 5.0.6. It is,
therefore, affected by a privilege elevation vulnerability. An authenticated, local attacker can exploit this to elevate
their privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  script_set_attribute(attribute:"see_also", value:"https://devblogs.microsoft.com/dotnet/net-may-2021/");
  # https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.15/3.1.15.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf5a364b");
  # https://github.com/dotnet/core/blob/main/release-notes/5.0/5.0.6/5.0.6.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f5cbba7");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_dotnet_core_installed.nbin");
  script_require_keys("installed_sw/.NET Core MacOS");

  exit(0);
}

include('vcf.inc');

var app = '.NET Core MacOS';
var app_info = vcf::get_app_info(app:app);

var constraints = [
  { 'min_version' : '3.1',     'fixed_version' : '3.1.15' },
  { 'min_version' : '5.0',     'fixed_version' : '5.0.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
