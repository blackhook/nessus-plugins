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
  script_id(131939);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id(
    "CVE-2019-1349",
    "CVE-2019-1350",
    "CVE-2019-1351",
    "CVE-2019-1352",
    "CVE-2019-1354",
    "CVE-2019-1387",
    "CVE-2019-1486"
  );

  script_name(english:"Security Updates for Microsoft Visual Studio Products (December 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

  - A tampering vulnerability exists when Git for Visual
    Studio improperly handles virtual drive paths. An
    attacker who successfully exploited this vulnerability
    could write arbitrary files and directories to certain
    locations on a vulnerable system. However, an attacker
    would have limited control over the destination of the
    files and directories.  (CVE-2019-1351)

  - A remote code execution vulnerability exists when Git
    for Visual Studio improperly sanitizes input. An
    attacker who successfully exploited this vulnerability
    could take control of an affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    Users whose accounts are configured to have fewer user
    rights on the system could be less impacted than users
    who operate with administrative user rights.
    (CVE-2019-1349, CVE-2019-1350, CVE-2019-1352,
    CVE-2019-1354, CVE-2019-1387)

  - A spoofing vulnerability exists in Visual Studio Live
    Share when a guest connected to a Live Share session is
    redirected to an arbitrary URL specified by the session
    host. An attacker who successfully exploited this
    vulnerability could cause a connected guest's computer
    to open a browser and navigate to a URL without consent
    from the guest.  (CVE-2019-1486)");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#-visual-studio-2017-version-15918-
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12d98124");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#--visual-studio-2019-version-1641-
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e082ad");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.0#--visual-studio-2019-version-16010-
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4bf32ac");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released Visual Studio 2017 15.9.18, Visual Studio 2019 16.0.19,
and Visual Studio 2019 16.4.1 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1354");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include('audit.inc');
include('misc_func.inc');
include('install_func.inc');
include('global_settings.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');

port = kb_smb_transport();
appname = 'Microsoft Visual Studio';

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  prod = install['product_version'];

  fix = '';

  # VS 2017 version 15.9
  if (prod == '2017' && version =~ '^15\\.[0-9]\\.')
  {
    fix = '15.9.28307.960';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.0
  else if (prod == '2019' && version =~ '^16\\.0\\.')
  {
    fix = '16.0.28803.631';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.4
  else if (prod == '2019' && version =~ '^16\\.[1-4]\\.')
  {
    fix = '16.4.29609.76';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
}

if (empty(report))
  audit(AUDIT_INST_VER_NOT_VULN, appname);

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
