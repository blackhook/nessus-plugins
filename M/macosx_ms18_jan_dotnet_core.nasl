#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#


include("compat.inc");

if (description)
{
  script_id(105729);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-0764", "CVE-2018-0786");

  script_name(english:"Security Update for .NET Core (January 2018) (macOS)");
  script_summary(english:"Checks the version of the .NET Core runtime.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core runtime installed on the remote macOS
or Mac OS X host is missing a security update. It is, therefore,
affected by multiple vulnerabilities :

  - A security feature bypass in X509 Certificate Validation
    allows an attacker to present a certificate that is
    marked as invalid for a specific use, but a component
    uses it for that purpose. (CVE-2018-0786)

  - A denial of service vulnerability exists due to improper
     processing of XML documents. An attacker who
     successfully exploited this vulnerability could cause
     a denial of service against a .NET application. A
     remote unauthenticated attacker could exploit this
     vulnerability by issuing specially crafted requests
     to a .NET Core application. (CVE-2018-0764)");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/51");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/52");
  # https://blogs.msdn.microsoft.com/dotnet/2018/01/09/net-core-january-2018-update/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebdb4bc7");
  # https://github.com/dotnet/core/blob/master/release-notes/1.0/1.0.9.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ee5ffe3");
  # https://github.com/dotnet/core/blob/master/release-notes/1.1/1.1.6.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1e826f0");
  # https://github.com/dotnet/core/blob/master/release-notes/2.0/2.0.5.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a103486");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0786
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3759d74b");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0764
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf7d5ce3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to .NET Core Runtime version 1.0.9 / 1.1.6 / 2.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_dotnet_core_installed.nbin");
  script_require_keys("installed_sw/.NET Core MacOS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = ".NET Core MacOS";

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
fix_ver = "2.0.5";
version = install['version'];

if (ver_compare(ver: version, fix: fix_ver) < 0)
{
  report =
    '\n  Path              : ' + install['path'] +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_ver +
    '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
  exit(0);
}

audit(AUDIT_INST_VER_NOT_VULN, app, version);
