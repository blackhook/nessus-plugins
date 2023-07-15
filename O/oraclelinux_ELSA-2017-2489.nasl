#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2489 and 
# Oracle Linux Security Advisory ELSA-2017-2489 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102571);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-1000115", "CVE-2017-1000116");
  script_xref(name:"RHSA", value:"2017:2489");

  script_name(english:"Oracle Linux 7 : mercurial (ELSA-2017-2489)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2489 :

An update for mercurial is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mercurial is a fast, lightweight source control management system
designed for efficient handling of very large distributed projects.

Security Fix(es) :

* A vulnerability was found in the way Mercurial handles path auditing
and caches the results. An attacker could abuse a repository with a
series of commits mixing symlinks and regular files/directories to
trick Mercurial into writing outside of a given repository.
(CVE-2017-1000115)

* A shell command injection flaw related to the handling of 'ssh' URLs
has been discovered in Mercurial. This can be exploited to execute
shell commands with the privileges of the user running the Mercurial
client, for example, when performing a 'checkout' or 'update' action
on a sub-repository within a malicious repository or a legitimate
repository containing a malicious commit. (CVE-2017-1000116)

Red Hat would like to thank the Mercurial Security Team for reporting
CVE-2017-1000115 and the Subversion Team for reporting
CVE-2017-1000116."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007138.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mercurial packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:emacs-mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:emacs-mercurial-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mercurial-hgk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"emacs-mercurial-2.6.2-8.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"emacs-mercurial-el-2.6.2-8.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mercurial-2.6.2-8.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mercurial-hgk-2.6.2-8.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-mercurial / emacs-mercurial-el / mercurial / mercurial-hgk");
}
