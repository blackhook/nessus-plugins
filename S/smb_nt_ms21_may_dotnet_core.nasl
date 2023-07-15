#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/05/13. Deprecated by macos_ms21_may_dotnet_core.nasl.
include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149438);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-31204");
  script_xref(name:"IAVA", value:"2021-A-0218-S");

  script_name(english:"Security Update for .NET Core (May 2021) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This  plugin has been deprecated by macos_ms21_may_dotnet_core.nasl (plugin ID 149472). CVE-2021-31204 does not apply
to Windows.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  script_set_attribute(attribute:"see_also", value:"https://devblogs.microsoft.com/dotnet/net-may-2021/");
  # https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.15/3.1.15.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf5a364b");
  # https://github.com/dotnet/core/blob/main/release-notes/5.0/5.0.6/5.0.6.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f5cbba7");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use macos_ms21_may_dotnet_core.nasl (plugin ID 149472) instead.');
