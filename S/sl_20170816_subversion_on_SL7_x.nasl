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
  script_id(102673);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-9800");

  script_name(english:"Scientific Linux Security Update : subversion on SL7.x x86_64 (20170816)");
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
"Security Fix(es) :

  - A shell command injection flaw related to the handling
    of 'svn+ssh' URLs has been discovered in Subversion. An
    attacker could use this flaw to execute shell commands
    with the privileges of the user running the Subversion
    client, for example when performing a 'checkout' or
    'update' action on a malicious repository, or a
    legitimate repository containing a malicious commit.
    (CVE-2017-9800)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1708&L=scientific-linux-errata&F=&S=&P=2798
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cde0487"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_dav_svn-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-debuginfo-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-devel-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-gnome-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-javahl-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-kde-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-libs-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-perl-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-python-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-ruby-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-tools-1.7.14-11.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-debuginfo / subversion-devel / etc");
}
