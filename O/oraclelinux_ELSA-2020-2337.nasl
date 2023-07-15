#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2337 and 
# Oracle Linux Security Advisory ELSA-2020-2337 respectively.
#

include("compat.inc");

if (description)
{
  script_id(136958);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/10");

  script_cve_id("CVE-2020-11008");
  script_xref(name:"RHSA", value:"2020:2337");

  script_name(english:"Oracle Linux 7 : git (ELSA-2020-2337)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2020:2337 :

The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:2337 advisory.

  - git: Crafted URL containing new lines, empty host or
    lacks a scheme can cause credential leak
    (CVE-2020-11008)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-May/009982.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"emacs-git-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"emacs-git-el-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-all-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-bzr-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-cvs-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-daemon-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-email-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-gnome-keyring-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-gui-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-hg-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-instaweb-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-p4-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-svn-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gitk-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gitweb-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perl-Git-1.8.3.1-23.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perl-Git-SVN-1.8.3.1-23.el7_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
}
