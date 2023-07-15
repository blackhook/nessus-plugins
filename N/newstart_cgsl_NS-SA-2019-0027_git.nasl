#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0027. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127189);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-11235");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : git Vulnerability (NS-SA-2019-0027)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has git packages installed that are affected by a
vulnerability:

  - In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x
    before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before
    2.17.1, remote code execution can occur. With a crafted
    .gitmodules file, a malicious project can execute an
    arbitrary script on a machine that runs git clone
    --recurse-submodules because submodule names are
    obtained from this file, and then appended to
    $GIT_DIR/modules, leading to directory traversal with
    ../ in a name. Finally, post-checkout hooks from a
    submodule are executed, bypassing the intended design in
    which hooks are not obtained from a remote server.
    (CVE-2018-11235)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0027");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL git packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11235");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "emacs-git-1.8.3.1-14.el7_5",
    "emacs-git-el-1.8.3.1-14.el7_5",
    "git-1.8.3.1-14.el7_5",
    "git-all-1.8.3.1-14.el7_5",
    "git-bzr-1.8.3.1-14.el7_5",
    "git-cvs-1.8.3.1-14.el7_5",
    "git-daemon-1.8.3.1-14.el7_5",
    "git-debuginfo-1.8.3.1-14.el7_5",
    "git-email-1.8.3.1-14.el7_5",
    "git-gui-1.8.3.1-14.el7_5",
    "git-hg-1.8.3.1-14.el7_5",
    "git-p4-1.8.3.1-14.el7_5",
    "git-svn-1.8.3.1-14.el7_5",
    "gitk-1.8.3.1-14.el7_5",
    "gitweb-1.8.3.1-14.el7_5",
    "perl-Git-1.8.3.1-14.el7_5",
    "perl-Git-SVN-1.8.3.1-14.el7_5"
  ],
  "CGSL MAIN 5.04": [
    "emacs-git-1.8.3.1-14.el7_5",
    "emacs-git-el-1.8.3.1-14.el7_5",
    "git-1.8.3.1-14.el7_5",
    "git-all-1.8.3.1-14.el7_5",
    "git-bzr-1.8.3.1-14.el7_5",
    "git-cvs-1.8.3.1-14.el7_5",
    "git-daemon-1.8.3.1-14.el7_5",
    "git-debuginfo-1.8.3.1-14.el7_5",
    "git-email-1.8.3.1-14.el7_5",
    "git-gui-1.8.3.1-14.el7_5",
    "git-hg-1.8.3.1-14.el7_5",
    "git-p4-1.8.3.1-14.el7_5",
    "git-svn-1.8.3.1-14.el7_5",
    "gitk-1.8.3.1-14.el7_5",
    "gitweb-1.8.3.1-14.el7_5",
    "perl-Git-1.8.3.1-14.el7_5",
    "perl-Git-SVN-1.8.3.1-14.el7_5"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git");
}
