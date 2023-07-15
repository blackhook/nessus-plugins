#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(132993);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/15");

  script_cve_id("CVE-2020-0605", "CVE-2020-0606");
  script_xref(name:"IAVA", value:"2020-A-0031-S");

  script_name(english:"Security Update for .NET Core (January 2020)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple .NET Core vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core installation on the remote host is version 3.0.x < 3.0.2 or 3.1.x < 3.1.1. It is, therefore,
affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists in .NET software when the software fails to check the source markup of
    a file. An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the
    current user. If the current user is logged on with administrative user rights, an attacker could take control of
    the affected system. An attacker could then install programs; view, change, or delete data; or create new accounts
    with full user rights. Users whose accounts are configured to have fewer user rights on the system could be less
    impacted than users who operate with administrative user rights. (CVE-2020-0605, CVE-2020-0606)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0605
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e287012");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0606
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa0a6c3c");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/148");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/149");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');

app = '.NET Core Windows';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '3.0.0', 'fixed_version' : '3.0.2' },
  { 'min_version' : '3.1.0', 'fixed_version' : '3.1.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

