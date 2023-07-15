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
  script_id(62918);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Scientific Linux Security Update : selinux-policy enhancement update on SL6.x i386/x86_64 (20121112)");
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
"This update adds the following enhancements :

  - Previously, SELinux was blocking the
    /usr/libexec/qemu-kvm utility during a migration of a
    virtual machine from Red Hat Enterprise Virtualization
    Manager. Consequently, such a migration attempt failed
    and AVC messages were returned. This update fixes the
    virt_use_fusefs boolean and adds the sanlock_use_fusefs
    boolean, thus allowing the migration to succeed in the
    described scenario.

  - When trying to start a virtual machine on a
    POSIX-compliant file system, SELinux denied the
    operation and returned AVC messages. This update amends
    the SELinux policy to allow the described scenario to
    succeed.

This update has been placed in the security tree to avoid selinux
bugs."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1211&L=scientific-linux-errata&T=0&P=817
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f25ffe5d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy-minimum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy-mls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy-targeted");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");
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


flag = 0;
if (rpm_check(release:"SL6", reference:"selinux-policy-3.7.19-155.el6_3.6")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-doc-3.7.19-155.el6_3.6")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-minimum-3.7.19-155.el6_3.6")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-mls-3.7.19-155.el6_3.6")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-targeted-3.7.19-155.el6_3.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "selinux-policy / selinux-policy-doc / selinux-policy-minimum / etc");
}
