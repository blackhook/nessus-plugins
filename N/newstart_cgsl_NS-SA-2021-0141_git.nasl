#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0141. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154511);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2020-11008");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : git Vulnerability (NS-SA-2021-0141)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has git packages installed that are affected by a
vulnerability:

  - Affected versions of Git have a vulnerability whereby Git can be tricked into sending private credentials
    to a host controlled by an attacker. This bug is similar to CVE-2020-5260(GHSA-qm7j-c969-7j4q). The fix
    for that bug still left the door open for an exploit where _some_ credential is leaked (but the attacker
    cannot control which one). Git uses external credential helper programs to store and retrieve passwords
    or other credentials from secure storage provided by the operating system. Specially-crafted URLs that are
    considered illegal as of the recently published Git versions can cause Git to send a blank pattern to
    helpers, missing hostname and protocol fields. Many helpers will interpret this as matching _any_ URL, and
    will return some unspecified stored password, leaking the password to an attacker's server. The
    vulnerability can be triggered by feeding a malicious URL to `git clone`. However, the affected URLs look
    rather suspicious; the likely vector would be through systems which automatically clone URLs not visible
    to the user, such as Git submodules, or package systems built around Git. The root of the problem is in
    Git itself, which should not be feeding blank input to helpers. However, the ability to exploit the
    vulnerability in practice depends on which helpers are in use. Credential helpers which are known to
    trigger the vulnerability: - Git's store helper - Git's cache helper - the osxkeychain helper that
    ships in Git's contrib directory Credential helpers which are known to be safe even with vulnerable
    versions of Git: - Git Credential Manager for Windows Any helper not in this list should be assumed to
    trigger the vulnerability. (CVE-2020-11008)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0141");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11008");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL git packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'emacs-git-1.8.3.1-23.el7_8',
    'emacs-git-el-1.8.3.1-23.el7_8',
    'git-1.8.3.1-23.el7_8',
    'git-all-1.8.3.1-23.el7_8',
    'git-bzr-1.8.3.1-23.el7_8',
    'git-cvs-1.8.3.1-23.el7_8',
    'git-daemon-1.8.3.1-23.el7_8',
    'git-debuginfo-1.8.3.1-23.el7_8',
    'git-email-1.8.3.1-23.el7_8',
    'git-gnome-keyring-1.8.3.1-23.el7_8',
    'git-gui-1.8.3.1-23.el7_8',
    'git-hg-1.8.3.1-23.el7_8',
    'git-instaweb-1.8.3.1-23.el7_8',
    'git-p4-1.8.3.1-23.el7_8',
    'git-svn-1.8.3.1-23.el7_8',
    'gitk-1.8.3.1-23.el7_8',
    'gitweb-1.8.3.1-23.el7_8',
    'perl-Git-1.8.3.1-23.el7_8',
    'perl-Git-SVN-1.8.3.1-23.el7_8'
  ],
  'CGSL MAIN 5.05': [
    'emacs-git-1.8.3.1-23.el7_8',
    'emacs-git-el-1.8.3.1-23.el7_8',
    'git-1.8.3.1-23.el7_8',
    'git-all-1.8.3.1-23.el7_8',
    'git-bzr-1.8.3.1-23.el7_8',
    'git-cvs-1.8.3.1-23.el7_8',
    'git-daemon-1.8.3.1-23.el7_8',
    'git-debuginfo-1.8.3.1-23.el7_8',
    'git-email-1.8.3.1-23.el7_8',
    'git-gnome-keyring-1.8.3.1-23.el7_8',
    'git-gui-1.8.3.1-23.el7_8',
    'git-hg-1.8.3.1-23.el7_8',
    'git-instaweb-1.8.3.1-23.el7_8',
    'git-p4-1.8.3.1-23.el7_8',
    'git-svn-1.8.3.1-23.el7_8',
    'gitk-1.8.3.1-23.el7_8',
    'gitweb-1.8.3.1-23.el7_8',
    'perl-Git-1.8.3.1-23.el7_8',
    'perl-Git-SVN-1.8.3.1-23.el7_8'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git');
}
