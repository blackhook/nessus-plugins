#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110270);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-11233", "CVE-2018-11235");

  script_name(english:"Git for Windows 2.13.x < 2.13.7 / 2.14.x < 2.14.4 / 2.15.x < 2.15.2 / 2.16.x < 2.16.4 / 2.17.x < 2.17.1 Remote Code Execution");
  script_summary(english:"Checks the version of git.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
  by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Git for Windows installed on the remote host is 2.13.x
  prior to 2.13.7, 2.14.x prior to 2.14.4, 2.15.x prior to 2.15.2,
  2.16.x prior to 2.16.4 or 2.17.x prior to 2.17.1. It is,
  therefore, affected by a remote code execution vulnerability.");
  # https://marc.info/?l=git&amp;m=152761328506724&amp;w=2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b8dff24");
  # https://github.com/git-for-windows/git/releases/tag/v2.17.1.windows.2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1267c9c");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.13.7.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f45ca93");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.14.4.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbe82e91");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.15.2.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff69b9fa");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.16.4.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c6c2dec");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.17.1.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d150bb79");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Git for Windows 2.13.7 / 2.14.4 / 2.15.2 / 2.16.4 / 2.17.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git_for_windows_project:git_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("git_for_windows_installed.nbin");
  script_require_keys("installed_sw/Git for Windows");

  exit(0);
}

include("vcf.inc");

app_name = "Git for Windows";

app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.13", "fixed_version" : "2.13.7" },
  { "min_version" : "2.14", "fixed_version" : "2.14.4" },
  { "min_version" : "2.15", "fixed_version" : "2.15.2" },
  { "min_version" : "2.16", "fixed_version" : "2.16.4" },
  { "min_version" : "2.17", "fixed_version" : "2.17.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
