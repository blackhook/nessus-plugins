#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0036. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138775);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2020-11008");

  script_name(english:"NewStart CGSL MAIN 6.01 : git Vulnerability (NS-SA-2020-0036)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.01, has git packages installed that are affected by a
vulnerability:

  - Affected versions of Git have a vulnerability whereby
    Git can be tricked into sending private credentials to a
    host controlled by an attacker. This bug is similar to
    CVE-2020-5260(GHSA-qm7j-c969-7j4q). The fix for that bug
    still left the door open for an exploit where _some_
    credential is leaked (but the attacker cannot control
    which one). Git uses external credential helper
    programs to store and retrieve passwords or other
    credentials from secure storage provided by the
    operating system. Specially-crafted URLs that are
    considered illegal as of the recently published Git
    versions can cause Git to send a blank pattern to
    helpers, missing hostname and protocol fields. Many
    helpers will interpret this as matching _any_ URL, and
    will return some unspecified stored password, leaking
    the password to an attacker's server. The vulnerability
    can be triggered by feeding a malicious URL to `git
    clone`. However, the affected URLs look rather
    suspicious; the likely vector would be through systems
    which automatically clone URLs not visible to the user,
    such as Git submodules, or package systems built around
    Git. The root of the problem is in Git itself, which
    should not be feeding blank input to helpers. However,
    the ability to exploit the vulnerability in practice
    depends on which helpers are in use. Credential helpers
    which are known to trigger the vulnerability: - Git's
    store helper - Git's cache helper - the
    osxkeychain helper that ships in Git's contrib
    directory Credential helpers which are known to be safe
    even with vulnerable versions of Git: - Git Credential
    Manager for Windows Any helper not in this list should
    be assumed to trigger the vulnerability.
    (CVE-2020-11008)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0036");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL git packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 6.01")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.01');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 6.01": [
    "git-2.18.4-2.el8_2",
    "git-all-2.18.4-2.el8_2",
    "git-core-2.18.4-2.el8_2",
    "git-core-debuginfo-2.18.4-2.el8_2",
    "git-core-doc-2.18.4-2.el8_2",
    "git-daemon-2.18.4-2.el8_2",
    "git-daemon-debuginfo-2.18.4-2.el8_2",
    "git-debuginfo-2.18.4-2.el8_2",
    "git-debugsource-2.18.4-2.el8_2",
    "git-email-2.18.4-2.el8_2",
    "git-gui-2.18.4-2.el8_2",
    "git-instaweb-2.18.4-2.el8_2",
    "git-subtree-2.18.4-2.el8_2",
    "git-svn-2.18.4-2.el8_2",
    "git-svn-debuginfo-2.18.4-2.el8_2",
    "gitk-2.18.4-2.el8_2",
    "gitweb-2.18.4-2.el8_2",
    "perl-Git-2.18.4-2.el8_2",
    "perl-Git-SVN-2.18.4-2.el8_2"
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
