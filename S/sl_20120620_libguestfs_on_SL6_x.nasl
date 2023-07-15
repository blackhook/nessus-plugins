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
  script_id(61339);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2690");

  script_name(english:"Scientific Linux Security Update : libguestfs on SL6.x x86_64 (20120620)");
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
"libguestfs is a library for accessing and modifying guest disk images.

It was found that editing files with virt-edit left said files in a
world-readable state (and did not preserve the file owner or
Security-Enhanced Linux context). If an administrator on the host used
virt-edit to edit a file inside a guest, the file would be left with
world-readable permissions. This could lead to unprivileged guest
users accessing files they would otherwise be unable to.
(CVE-2012-2690)

These updated libguestfs packages include numerous bug fixes and
enhancements.

Users of libguestfs are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=3608
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55e94b95"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-debuginfo-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-devel-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-java-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-java-devel-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-javadoc-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-tools-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-tools-c-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ocaml-libguestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"python-libguestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ruby-libguestfs-1.16.19-1.el6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libguestfs / libguestfs-debuginfo / libguestfs-devel / etc");
}
