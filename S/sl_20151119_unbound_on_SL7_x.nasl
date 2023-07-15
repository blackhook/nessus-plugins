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
  script_id(87577);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-8602");

  script_name(english:"Scientific Linux Security Update : unbound on SL7.x x86_64 (20151119)");
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
"A denial of service flaw was found in unbound that an attacker could
use to trick the unbound resolver into following an endless loop of
delegations, consuming an excessive amount of resources.
(CVE-2014-8602)

This update also fixes the following bugs :

  - Prior to this update, there was a mistake in the time
    configuration in the cron job invoking unbound-anchor to
    update the root zone key. Consequently, unbound-anchor
    was invoked once a month instead of every day, thus not
    complying with RFC 5011. The cron job has been replaced
    with a systemd timer unit that is invoked on a daily
    basis. Now, the root zone key validity is checked daily
    at a random time within a 24-hour window, and compliance
    with RFC 5011 is ensured.

  - Previously, the unbound packages were installing their
    configuration file for the systemd-tmpfiles utility into
    the /etc/tmpfiles.d/ directory. As a consequence,
    changes to unbound made by the administrator in
    /etc/tmpfiles.d/ could be overwritten on package
    reinstallation or update. To fix this bug, unbound has
    been amended to install the configuration file into the
    /usr/lib/tmpfiles.d/ directory. As a result, the system
    administrator's configuration in /etc/tmpfiles.d/ is
    preserved, including any changes, on package
    reinstallation or update.

  - The unbound server default configuration included
    validation of DNS records using the DNSSEC Look-aside
    Validation (DLV) registry. The Internet Systems
    Consortium (ISC) plans to deprecate the DLV registry
    service as no longer needed, and unbound could execute
    unnecessary steps. Therefore, the use of the DLV
    registry has been removed from the unbound server
    default configuration. Now, unbound does not try to
    perform DNS records validation using the DLV registry."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=5249
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ad4510a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:unbound-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:unbound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:unbound-python");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-1.4.20-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-debuginfo-1.4.20-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-devel-1.4.20-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-libs-1.4.20-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-python-1.4.20-26.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "unbound / unbound-debuginfo / unbound-devel / unbound-libs / etc");
}
