#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
 ##

include('compat.inc');

if (description)
{
  script_id(172528);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id(
    "CVE-2023-22490",
    "CVE-2023-22743",
    "CVE-2023-23618",
    "CVE-2023-23946"
  );
  script_xref(name:"IAVA", value:"2023-A-0138-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (Mar 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - Using a specially-crafted repository, Git prior to versions 2.39.2, 2.38.4, 2.37.6, 2.36.5, 2.35.7, 2.34.7, 2.33.7, 
    2.32.6, 2.31.7, and 2.30.8 can be tricked into using its local clone optimization even when using a non-local transport.
    As a workaround, avoid cloning repositories from untrusted sources with --recurse-submodules. Instead, consider cloning 
    repositories without recursively cloning their submodules, and instead run git submodule update at each layer. Before 
    doing so, inspect each new .gitmodules file to ensure that it does not contain suspicious module URLs. (CVE-2023-22490)

  - Prior to Git for Windows version 2.39.2, by carefully crafting DLL and putting into a subdirectory of a specific name 
    living next to the Git for Windows installer, Windows can be tricked into side-loading said DLL. This potentially allows 
    users with local write access to place malicious payloads in a location where automated upgrades might run the Git for Windows
    installer with elevation. If upgrading is impractical, never leave untrusted files in the Downloads folder or its sub-folders 
    before executing the Git for Windows installer, or move the installer into a different directory before executing it.
    (CVE-2023-22743)

  - Prior to Git for Windows version 2.39.2, when gitk is run on Windows, it potentially runs executables from the current directory
    inadvertently, which can be exploited with some social engineering to trick users into running untrusted code. As a workaround, 
    avoid using gitk (or Git Visualize History functionality) in clones of untrusted repositories. (CVE-2023-23618)

  - Git is vulnerable to path traversal prior to versions 2.39.2, 2.38.4, 2.37.6, 2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 
    2.30.8. By feeding a crafted input to git apply, a path outside the working tree can be overwritten as the user who is running 
    git apply. As a workaround, use git apply --stat to inspect a patch before applying; avoid applying one that creates a symbolic 
    link and then creates a file beyond the symbolic link. (CVE-2023-23946)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.5.2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f02327c");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17.4.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?def7f2c2");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17.2.14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7a78ad8");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17.0.20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd9fbab5");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.25
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21c60220");
  # https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.53
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f103f693");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 15.9.53 for Visual Studio 2017
        - Update 16.11.25 for Visual Studio 2019
        - Update 17.0.20 for Visual Studio 2022
        - Update 17.2.14 for Visual Studio 2022
        - Update 17.4.6 for Visual Studio 2022
        - Update 17.5.2 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23946");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-23618");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2017', 'min_version': '15.0', 'fixed_version': '15.9.33423.255', 'fixed_display': '15.9.33423.255 (15.9.53)'},
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.33423.256', 'fixed_display': '16.11.33423.256 (16.11.25)'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.33502.349', 'fixed_display': '17.0.33502.349 (17.0.20)'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.33502.348', 'fixed_display': '17.2.33502.348 (17.2.14)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.33502.350', 'fixed_display': '17.4.33502.350 (17.4.6)'},
  {'product': '2022', 'min_version': '17.5', 'fixed_version': '17.5.33424.131', 'fixed_display': '17.5.33424.131 (17.5.2)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
