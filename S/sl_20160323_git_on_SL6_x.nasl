#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90143);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-2315", "CVE-2016-2324");

  script_name(english:"Scientific Linux Security Update : git on SL6.x, SL7.x i386/x86_64 (20160323)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer truncation flaw and an integer overflow flaw, both leading
to a heap-based buffer overflow, were found in the way Git processed
certain path information. A remote attacker could create a specially
crafted Git repository that would cause a Git client or server to
crash or, possibly, execute arbitrary code. (CVE-2016-2315,
CVE-2016-2324)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1603&L=scientific-linux-errata&F=&S=&P=12617
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89482cae"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"emacs-git-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"emacs-git-el-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-all-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-cvs-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-daemon-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-debuginfo-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-email-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-gui-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-svn-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"gitk-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"gitweb-1.7.1-4.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Git-1.7.1-4.el6_7.1")) flag++;

if (rpm_check(release:"SL7", reference:"emacs-git-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"emacs-git-el-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"git-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"git-all-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"git-bzr-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"git-cvs-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"git-daemon-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"git-debuginfo-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"git-email-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"git-gui-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"git-hg-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"git-p4-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"git-svn-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"gitk-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"gitweb-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Git-1.8.3.1-6.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Git-SVN-1.8.3.1-6.el7_2.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
}
