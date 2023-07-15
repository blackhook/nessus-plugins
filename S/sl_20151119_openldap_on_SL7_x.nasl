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
  script_id(87566);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-3276");

  script_name(english:"Scientific Linux Security Update : openldap on SL7.x x86_64 (20151119)");
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
"A flaw was found in the way OpenLDAP parsed OpenSSL-style cipher
strings. As a result, OpenLDAP could potentially use ciphers that were
not intended to be enabled. (CVE-2015-3276)

The openldap packages have been upgraded to upstream version 2.4.40,
which provides a number of bug fixes and one enhancement over the
previous version :

  - The ORDERING matching rules have been added to the
    ppolicy attribute type descriptions. * The server no
    longer terminates unexpectedly when processing SRV
    records. * Missing objectClass information has been
    added, which enables the user to modify the front-end
    configuration by standard means.

This update also fixes the following bugs :

  - Previously, OpenLDAP did not properly handle a number of
    simultaneous updates. As a consequence, sending a number
    of parallel update requests to the server could cause a
    deadlock. With this update, a superfluous locking
    mechanism causing the deadlock has been removed, thus
    fixing the bug.

  - The httpd service sometimes terminated unexpectedly with
    a segmentation fault on the libldap library unload. The
    underlying source code has been modified to prevent a
    bad memory access error that caused the bug to occur. As
    a result, httpd no longer crashes in this situation.

  - After upgrading the system from Scientific Linux 6 to
    Scientific Linux 7, symbolic links to certain libraries
    unexpectedly pointed to locations belonging to the
    openldap-devel package. If the user uninstalled
    openldap- devel, the symbolic links were broken and the
    'rpm -V openldap' command sometimes produced errors.
    With this update, the symbolic links no longer get
    broken in the described situation. If the user
    downgrades openldap to version 2.4.39-6 or earlier, the
    symbolic links might break. After such downgrade, it is
    recommended to verify that the symbolic links did not
    break. To do this, make sure the yum-plugin-verify
    package is installed and obtain the target libraries by
    running the 'rpm -V openldap' or 'yum verify openldap'
    command.

In addition, this update adds the following enhancement :

  - OpenLDAP clients now automatically choose the Network
    Security Services (NSS) default cipher suites for
    communication with the server. It is no longer necessary
    to maintain the default cipher suites manually in the
    OpenLDAP source code."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=9879
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d769fef6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/07");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-2.4.40-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-clients-2.4.40-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-debuginfo-2.4.40-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-devel-2.4.40-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-servers-2.4.40-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-servers-sql-2.4.40-8.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients / openldap-debuginfo / openldap-devel / etc");
}
