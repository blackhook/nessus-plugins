#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146344);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-1721");

  script_name(english:"Security Update for Microsoft ASP.NET Core (February 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET Core installations on the remote host contain vulnerable packages.");
  script_set_attribute(attribute:"description", value:
"The Microsoft ASP.NET Core installation on the remote host is version 2.1.x prior to 2.1.25, 3.1.x prior to 3.1.126, or
5.x prior to 5.0.3. It is, therefore, affected by a denial of service vulnerability when creating HTTPS web requests
during X509 certificate chain building. An unauthenticated, remote attacker can exploit this to cause the application to
stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/2.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/175");
  # https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.25/2.1.25.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2455d834");
  # https://github.com/dotnet/core/blob/master/release-notes/3.1/3.1.12/3.1.12.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a75f459e");
  # https://github.com/dotnet/core/blob/master/release-notes/5.0/5.0.3/5.0.3.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51c16faa");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1721");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");

  exit(0);
}

include('vcf.inc');

app = 'ASP .NET Core Windows';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '2.1',     'fixed_version' : '2.1.25' },
  { 'min_version' : '3.1',     'fixed_version' : '3.1.12' },
  { 'min_version' : '5.0',     'fixed_version' : '5.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
