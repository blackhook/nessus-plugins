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
  script_id(61242);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Scientific Linux Security Update : selinux-policy on SL5.x i386/x86_64 (20120209)");
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
"The selinux-policy packages contain the rules that govern how confined
processes run on the system.

This update fixes the following bug :

  - With SELinux in enforcing mode, an Open MPI (Message
    Passing Interface) job submitted to the parallel
    universe environment failed when an attempt to generate
    SSH keys with the ssh-keygen utility was made. With this
    update, the 'ssh_keygen_t' SELinux domain type has been
    implemented as unconfined, which ensures the ssh-keygen
    utility to work correctly. (BZ#784782)

All users of selinux-policy are advised to upgrade to these updated
packages, which fix this bug."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=784782"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=1730
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?248f796d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy-minimum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy-mls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy-strict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:selinux-policy-targeted");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/09");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"selinux-policy-2.4.6-316.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-devel-2.4.6-316.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-minimum-2.4.6-316.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-mls-2.4.6-316.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-strict-2.4.6-316.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-targeted-2.4.6-316.el5_7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "selinux-policy / selinux-policy-devel / selinux-policy-minimum / etc");
}
