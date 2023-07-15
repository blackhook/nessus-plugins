#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:1932 and 
# Oracle Linux Security Advisory ELSA-2018-1932 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110707);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2014-10072", "CVE-2017-18206", "CVE-2018-1083", "CVE-2018-1100");
  script_xref(name:"RHSA", value:"2018:1932");

  script_name(english:"Oracle Linux 6 : zsh (ELSA-2018-1932)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:1932 :

An update for zsh is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The zsh shell is a command interpreter usable as an interactive login
shell and as a shell script command processor. Zsh resembles the ksh
shell (the Korn shell), but includes many enhancements. Zsh supports
command-line editing, built-in spelling correction, programmable
command completion, shell functions (with autoloading), a history
mechanism, and more.

Security Fix(es) :

* zsh: Stack-based buffer overflow in gen_matches_files() at compctl.c
(CVE-2018-1083)

* zsh: buffer overflow when scanning very long directory paths for
symbolic links (CVE-2014-10072)

* zsh: buffer overrun in symlinks (CVE-2017-18206)

* zsh: buffer overflow in utils.c:checkmailpath() can lead to local
arbitrary code execution (CVE-2018-1100)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

The CVE-2018-1083 and CVE-2018-1100 issues were discovered by Richard
Maciel Costa (Red Hat).

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.10 Release Notes and Red Hat Enterprise Linux 6.10
Technical Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-June/007812.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected zsh packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:zsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:zsh-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"zsh-4.3.11-8.el6")) flag++;
if (rpm_check(release:"EL6", reference:"zsh-html-4.3.11-8.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zsh / zsh-html");
}
