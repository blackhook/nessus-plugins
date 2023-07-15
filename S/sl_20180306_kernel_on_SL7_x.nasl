#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(107210);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2017-12188", "CVE-2017-7518");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64 (20180306)");
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

  - Kernel: KVM: MMU potential stack buffer overrun during
    page walks (CVE-2017-12188, Important)

  - Kernel: KVM: debug exception via syscall emulation
    (CVE-2017-7518, Moderate)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1803&L=scientific-linux-errata&F=&S=&P=1085
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84c84036"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-693.21.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-693.21.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
}
