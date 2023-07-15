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
  script_id(95843);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-8869");

  script_name(english:"Scientific Linux Security Update : libguestfs and virt-p2v on SL7.x x86_64 (20161103)");
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
"Virt-p2v is a tool for conversion of a physical server to a virtual
guest.

The following packages have been upgraded to a newer upstream version:
libguestfs (1.32.7), virt-p2v (1.32.7).

Security Fix(es) :

  - An integer conversion flaw was found in the way OCaml's
    String handled its length. Certain operations on an
    excessively long String could trigger a buffer overflow
    or result in an information leak. (CVE-2015-8869)

Note: The libguestfs packages in this advisory were rebuilt with a
fixed version of OCaml to address this issue.

Additional Changes :"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=8206
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aeb0986"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-gobject-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libguestfs-bash-completion-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-debuginfo-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-devel-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-gfs2-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-gobject-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-gobject-devel-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libguestfs-gobject-doc-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libguestfs-inspect-icons-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-java-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-java-devel-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libguestfs-javadoc-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libguestfs-man-pages-ja-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libguestfs-man-pages-uk-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-rescue-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-rsync-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libguestfs-tools-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-tools-c-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libguestfs-xfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"lua-guestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-libguestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-libguestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-libguestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"virt-dib-1.32.7-3.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libguestfs / libguestfs-bash-completion / libguestfs-debuginfo / etc");
}
