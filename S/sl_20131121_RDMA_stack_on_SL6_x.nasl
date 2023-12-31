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
  script_id(71294);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-4516", "CVE-2013-2561");

  script_name(english:"Scientific Linux Security Update : RDMA stack on SL6.x i386/x86_64 (20131121)");
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
"A flaw was found in the way ibutils handled temporary files. A local
attacker could use this flaw to cause arbitrary files to be
overwritten as the root user via a symbolic link attack.
(CVE-2013-2561)

It was discovered that librdmacm used a static port to connect to the
ib_acm service. A local attacker able to run a specially crafted
ib_acm service on that port could use this flaw to provide incorrect
address resolution information to librmdacm applications.
(CVE-2012-4516)

This advisory updates the following packages to the latest upstream
releases, providing a number of bug fixes and enhancements over the
previous versions :

Several bugs have been fixed in the openmpi, mpitests, ibutils, and
infinipath-psm packages.

The most notable changes in these updated packages from the RDMA stack
are the following :

  - Multiple bugs in the Message Passing Interface (MPI)
    test packages were resolved, allowing more of the
    mpitest applications to pass on the underlying MPI
    implementations.

  - The libmlx4 package now includes dracut module files to
    ensure that any necessary custom configuration of mlx4
    port types is included in the initramfs dracut builds.

  - Multiple test programs in the perftest and qperf
    packages now work properly over RoCE interfaces, or when
    specifying the use of rdmacm queue pairs.

  - The mstflint package has been updated to the latest
    upstream version, which is now capable of burning
    firmware on newly released Mellanox Connect-IB hardware.

  - A compatibility problem between the openmpi and
    infinipath-psm packages has been resolved with new
    builds of these packages."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=2821
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c449f74"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibutils-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infinipath-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infinipath-psm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infinipath-psm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libmlx4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libmlx4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libmlx4-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mpitests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mpitests-mvapich");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mpitests-mvapich-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mpitests-mvapich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mpitests-mvapich2-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mpitests-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mstflint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mstflint-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openmpi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perftest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perftest-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qperf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rdma");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"ibutils-1.5.7-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibutils-debuginfo-1.5.7-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibutils-devel-1.5.7-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibutils-libs-1.5.7-8.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"infinipath-psm-3.0.1-115.1015_open.2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"infinipath-psm-debuginfo-3.0.1-115.1015_open.2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"infinipath-psm-devel-3.0.1-115.1015_open.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-1.1.7-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-debuginfo-1.1.7-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-devel-1.1.7-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-devel-static-1.1.7-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-utils-1.1.7-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libmlx4-1.0.5-4.el6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libmlx4-debuginfo-1.0.5-4.el6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libmlx4-static-1.0.5-4.el6.1")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-1.0.17-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-debuginfo-1.0.17-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-devel-1.0.17-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-static-1.0.17-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-utils-1.0.17-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mpitests-debuginfo-3.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mpitests-mvapich-3.2-9.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"mpitests-mvapich-psm-3.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mpitests-mvapich2-3.2-9.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"mpitests-mvapich2-psm-3.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mpitests-openmpi-3.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mstflint-3.0-0.6.g6961daa.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mstflint-debuginfo-3.0-0.6.g6961daa.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openmpi-1.5.4-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openmpi-debuginfo-1.5.4-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openmpi-devel-1.5.4-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perftest-2.0-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perftest-debuginfo-2.0-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qperf-0.4.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qperf-debuginfo-0.4.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"rdma-3.10-3.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ibutils / ibutils-debuginfo / ibutils-devel / ibutils-libs / etc");
}
