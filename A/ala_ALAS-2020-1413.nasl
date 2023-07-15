#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1413.
#

include("compat.inc");

if (description)
{
  script_id(139093);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/13");

  script_cve_id("CVE-2020-11008", "CVE-2020-5260");
  script_xref(name:"ALAS", value:"2020-1413");

  script_name(english:"Amazon Linux AMI : git (ALAS-2020-1413)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Affected versions of Git have a vulnerability whereby Git can be
tricked into sending private credentials to a host controlled by an
attacker. This bug is similar to CVE-2020-5260 (GHSA-qm7j-c969-7j4q).
The fix for that bug still left the door open for an exploit where
_some_ credential is leaked (but the attacker cannot control which
one). Git uses external 'credential helper' programs to store and
retrieve passwords or other credentials from secure storage provided
by the operating system. Specially crafted URLs that are considered
illegal as of the recently published Git versions can cause Git to
send a 'blank' pattern to helpers, missing hostname and protocol
fields. Many helpers will interpret this as matching _any_ URL, and
will return some unspecified stored password, leaking the password to
an attacker's server. The vulnerability can be triggered by feeding a
malicious URL to `git clone`. However, the affected URLs look rather
suspicious; the likely vector would be through systems which
automatically clone URLs not visible to the user, such as Git
submodules, or package systems built around Git. The root of the
problem is in Git itself, which should not be feeding blank input to
helpers. However, the ability to exploit the vulnerability in practice
depends on which helpers are in use. Credential helpers which are
known to trigger the vulnerability: - Git's 'store' helper - Git's
'cache' helper - the 'osxkeychain' helper that ships in Git's
'contrib' directory Credential helpers which are known to be safe even
with vulnerable versions of Git: - Git Credential Manager for Windows
Any helper not in this list should be assumed to trigger the
vulnerability. (CVE-2020-11008)

Affected versions of Git have a vulnerability whereby Git can be
tricked into sending private credentials to a host controlled by an
attacker. Git uses external 'credential helper' programs to store and
retrieve passwords or other credentials from secure storage provided
by the operating system. Specially crafted URLs that contain an
encoded newline can inject unintended values into the credential
helper protocol stream, causing the credential helper to retrieve the
password for one server (e.g., good.example.com) for an HTTP request
being made to another server (e.g., evil.example.com), resulting in
credentials for the former being sent to the latter. There are no
restrictions on the relationship between the two, meaning that an
attacker can craft a URL that will present stored credentials for any
host to a host of their choosing. The vulnerability can be triggered
by feeding a malicious URL to git clone. However, the affected URLs
look rather suspicious; the likely vector would be through systems
which automatically clone URLs not visible to the user, such as Git
submodules, or package systems built around Git. The problem has been
patched in the versions published on April 14th, 2020, going back to
v2.17.x. Anyone wishing to backport the change further can do so by
applying commit 9a6bbee (the full release includes extra checks for
git fsck, but that commit is sufficient to protect clients against the
vulnerability). The patched versions are: 2.17.4, 2.18.3, 2.19.4,
2.20.3, 2.21.2, 2.22.3, 2.23.2, 2.24.2, 2.25.3, 2.26.1.
(CVE-2020-5260)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1413.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update git' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-subtree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"emacs-git-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"emacs-git-el-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-all-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-bzr-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-core-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-core-doc-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-cvs-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-daemon-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-debuginfo-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-email-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-hg-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-instaweb-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-p4-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-subtree-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-svn-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gitweb-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-2.18.4-2.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-SVN-2.18.4-2.71.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-core / etc");
}
