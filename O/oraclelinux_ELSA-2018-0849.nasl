#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:0849 and 
# Oracle Linux Security Advisory ELSA-2018-0849 respectively.
#

include("compat.inc");

if (description)
{
  script_id(109108);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2017-11671");
  script_xref(name:"RHSA", value:"2018:0849");

  script_name(english:"Oracle Linux 7 : gcc (ELSA-2018-0849)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:0849 :

An update for gcc is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The gcc packages provide compilers for C, C++, Java, Fortran,
Objective C, and Ada 95 GNU, as well as related support libraries.

Security Fix(es) :

* gcc: GCC generates incorrect code for RDRAND/RDSEED intrinsics
(CVE-2017-11671)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.5 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-April/007613.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gcc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libasan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgnat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgnat-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgo-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libitm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmudflap-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtsan-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cpp-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gcc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gcc-c++-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gcc-gfortran-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gcc-gnat-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gcc-go-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gcc-objc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gcc-objc++-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gcc-plugin-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libasan-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libasan-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libatomic-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libatomic-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgcc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgfortran-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgfortran-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgnat-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgnat-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgnat-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgo-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgo-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgo-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libgomp-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libitm-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libitm-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libitm-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libmudflap-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libmudflap-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libmudflap-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libobjc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libquadmath-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libquadmath-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libquadmath-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libstdc++-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libstdc++-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libstdc++-docs-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libstdc++-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libtsan-4.8.5-28.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libtsan-static-4.8.5-28.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / gcc / gcc-c++ / gcc-gfortran / gcc-gnat / gcc-go / gcc-objc / etc");
}
