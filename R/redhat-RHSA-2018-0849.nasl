#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0849. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108988);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id("CVE-2017-11671");
  script_xref(name:"RHSA", value:"2018:0849");

  script_name(english:"RHEL 7 : gcc (RHSA-2018:0849)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for gcc is now available for Red Hat Enterprise Linux 7.

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
  # https://access.redhat.com/documentation/en-US/red_hat_enterprise_linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dde41582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-11671"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libasan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgnat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgnat-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgo-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libitm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtsan-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:0849";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"cpp-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cpp-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gcc-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gcc-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gcc-base-debuginfo-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gcc-c++-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gcc-c++-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gcc-debuginfo-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gcc-gfortran-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gcc-gfortran-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gcc-gnat-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gcc-go-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gcc-go-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gcc-objc-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gcc-objc-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gcc-objc++-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gcc-objc++-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gcc-plugin-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gcc-plugin-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libasan-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libasan-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libasan-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libasan-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libatomic-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libatomic-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libgcc-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libgfortran-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libgfortran-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libgnat-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libgnat-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libgnat-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libgnat-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libgnat-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libgnat-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libgo-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libgo-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libgo-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libgomp-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libitm-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libitm-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libitm-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libmudflap-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libmudflap-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libmudflap-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libobjc-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libquadmath-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libquadmath-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libquadmath-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libquadmath-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libquadmath-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libquadmath-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libstdc++-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libstdc++-devel-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libstdc++-docs-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libstdc++-docs-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libstdc++-static-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libtsan-4.8.5-28.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libtsan-static-4.8.5-28.el7")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / gcc / gcc-base-debuginfo / gcc-c++ / gcc-debuginfo / etc");
  }
}
