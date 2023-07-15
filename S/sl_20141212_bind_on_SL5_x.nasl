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
  script_id(80020);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-8500");

  script_name(english:"Scientific Linux Security Update : bind on SL5.x, SL6.x, SL7.x i386/x86_64 (20141212)");
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
"A denial of service flaw was found in the way BIND followed DNS
delegations. A remote attacker could use a specially crafted zone
containing a large number of referrals which, when looked up and
processed, would cause named to use excessive amounts of memory or
crash. (CVE-2014-8500)

After installing the update, the BIND daemon (named) will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=2229
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1724d294"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"bind-9.3.6-25.P1.el5_11.2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-chroot-9.3.6-25.P1.el5_11.2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-debuginfo-9.3.6-25.P1.el5_11.2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-devel-9.3.6-25.P1.el5_11.2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libbind-devel-9.3.6-25.P1.el5_11.2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libs-9.3.6-25.P1.el5_11.2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-sdb-9.3.6-25.P1.el5_11.2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-utils-9.3.6-25.P1.el5_11.2")) flag++;
if (rpm_check(release:"SL5", reference:"caching-nameserver-9.3.6-25.P1.el5_11.2")) flag++;

if (rpm_check(release:"SL6", reference:"bind-9.8.2-0.30.rc1.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-chroot-9.8.2-0.30.rc1.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-debuginfo-9.8.2-0.30.rc1.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-devel-9.8.2-0.30.rc1.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-libs-9.8.2-0.30.rc1.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-sdb-9.8.2-0.30.rc1.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-utils-9.8.2-0.30.rc1.el6_6.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-chroot-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-debuginfo-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-devel-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-libs-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-libs-lite-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", reference:"bind-license-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-lite-devel-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-sdb-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-sdb-chroot-9.9.4-14.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-utils-9.9.4-14.el7_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / etc");
}
