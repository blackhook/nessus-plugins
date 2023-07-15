#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102494);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-1000117");

  script_name(english:"Git for Windows 2.7.x < 2.7.6 / 2.8.x < 2.8.6 / 2.9.x < 2.9.5 / 2.10.x < 2.10.4 / 2.11.x < 2.11.13 / 2.12.x < 2.12.4 / 2.13.x < 2.13.5 / 2.14.x < 2.14.1 Malicious SSH URL Command Execution");
  script_summary(english:"Checks the version of git.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Git for Windows installed on the remote host is version
2.7.x prior to 2.7.6, 2.8.x prior to 2.8.6, 2.9.x prior to 2.9.5,
2.10.x prior to 2.10.4, 2.11.x prior to 2.11.13, 2.12.x prior to
2.12.4, 2.13.x prior to 2.13.5, or 2.14.x prior to 2.14.1. It is,
therefore, affected by a command execution vulnerability due to a flaw
in the handling of 'ssh://' URLs that begin with a dash. A maliciously
crafted 'ssh://' URL causes Git clients to run an arbitrary shell
command. Such a URL could be placed in the .gitmodules file of a
malicious project, and an unsuspecting victim could be tricked into
running 'git clone --recurse-submodules' to trigger the vulnerability.");
  # https://public-inbox.org/git/xmqqh8xf482j.fsf@gitster.mtv.corp.google.com/T/#u
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?894dcb77");
  # https://github.com/git-for-windows/git/releases/tag/v2.14.1.windows.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0aca1c0");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.7.6.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4798389e");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.8.6.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a099ed51");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.9.5.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c6ad422");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.10.4.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a506ef2");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.11.13.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d9668c9");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.12.4.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d38639e5");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.13.5.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aea2c8f6");
  # https://github.com/git/git/blob/master/Documentation/RelNotes/2.14.1.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aafcb0d4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Git for Windows 2.7.6 / 2.8.6 / 2.9.5 / 2.10.4 / 2.11.13 / 2.12.4 / 2.13.5 / 2.14.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000117");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git HTTP Server For CVE-2017-1000117');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git_for_windows_project:git_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("git_for_windows_installed.nbin");
  script_require_keys("installed_sw/Git for Windows");

  exit(0);
}

include("vcf.inc");

app_name = "Git for Windows";

app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.7", "fixed_version" : "2.7.6" },
  { "min_version" : "2.8", "fixed_version" : "2.8.6" },
  { "min_version" : "2.9", "fixed_version" : "2.9.5" },
  { "min_version" : "2.10", "fixed_version" : "2.10.4" },
  { "min_version" : "2.11", "fixed_version" : "2.11.13" },
  { "min_version" : "2.12", "fixed_version" : "2.12.4" },
  { "min_version" : "2.13", "fixed_version" : "2.13.5" },
  { "min_version" : "2.14", "fixed_version" : "2.14.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
