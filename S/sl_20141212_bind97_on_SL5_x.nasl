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
  script_id(80019);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-8500");

  script_name(english:"Scientific Linux Security Update : bind97 on SL5.x i386/x86_64 (20141212)");
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
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=2102
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a69c3a9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind97-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind97-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind97-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind97-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind97-utils");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"bind97-9.7.0-21.P2.el5_11.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-chroot-9.7.0-21.P2.el5_11.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-debuginfo-9.7.0-21.P2.el5_11.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-devel-9.7.0-21.P2.el5_11.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-libs-9.7.0-21.P2.el5_11.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind97-utils-9.7.0-21.P2.el5_11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind97 / bind97-chroot / bind97-debuginfo / bind97-devel / etc");
}
