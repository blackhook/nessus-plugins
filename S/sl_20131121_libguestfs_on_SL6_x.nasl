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
  script_id(71194);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4419");

  script_name(english:"Scientific Linux Security Update : libguestfs on SL6.x x86_64 (20131121)");
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
"It was found that guestfish, which enables shell scripting and command
line access to libguestfs, insecurely created the temporary directory
used to store the network socket when started in server mode. A local
attacker could use this flaw to intercept and modify other user's
guestfish command, allowing them to perform arbitrary guestfish
actions with the privileges of a different user, or use this flaw to
obtain authentication credentials. (CVE-2013-4419)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=196
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c8ca699"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:febootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:febootstrap-supermin-helper");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"febootstrap-3.21-4.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"febootstrap-supermin-helper-3.21-4.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-debuginfo-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-devel-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-java-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-java-devel-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-javadoc-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-tools-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-tools-c-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ocaml-libguestfs-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"python-libguestfs-1.20.11-2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ruby-libguestfs-1.20.11-2.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "febootstrap / febootstrap-supermin-helper / libguestfs / etc");
}
