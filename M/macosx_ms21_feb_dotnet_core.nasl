#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(146347);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/01");

  script_cve_id("CVE-2021-1721", "CVE-2021-24112");

  script_name(english:"Security Update for .NET Core (February 2021) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core runtime installed on the remote macOS or Mac OS X host is missing a security update. It is,
therefore, affected by multiple vulnerabilities:

  - A denial of service vulnerability exists in .NET Core when creating HTTPS web requests during X509
    certificate chain building. An unauthenticated, remote attacker can exploit this to cause the application
    to stop responding. (CVE-2021-1721)

  - A remote code execution vulnerability exists in .NET Core when parsing certain types of graphics files. An
    unauthenticated, remote attacker can exploit this to execute arbitrary code. This vulnerability only
    exists on systems running on macOS or Linux. (CVE-2021-24112)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/2.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/175");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/176");
  # https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.25/2.1.25.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2455d834");
  # https://github.com/dotnet/core/blob/master/release-notes/3.1/3.1.12/3.1.12.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a75f459e");
  # https://github.com/dotnet/core/blob/master/release-notes/5.0/5.0.3/5.0.3.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51c16faa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to .NET Core Runtime version 2.1.25, 3.1.2, 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24112");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_dotnet_core_installed.nbin");
  script_require_keys("installed_sw/.NET Core MacOS");

  exit(0);
}

include('vcf.inc');

app = '.NET Core MacOS';

app_info = vcf::get_app_info(app:app);

constraints = [
  { 'min_version' : '2.1',     'fixed_version' : '2.1.25' },
  { 'min_version' : '3.1',     'fixed_version' : '3.1.12' },
  { 'min_version' : '5.0',     'fixed_version' : '5.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
