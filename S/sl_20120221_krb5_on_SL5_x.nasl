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
  script_id(61266);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-1526");

  script_name(english:"Scientific Linux Security Update : krb5 on SL5.x i386/x86_64 (20120221)");
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
"Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third party, the Key Distribution Center (KDC).

It was found that ftpd, a Kerberos-aware FTP server, did not properly
drop privileges. On Scientific Linux 5, the ftpd daemon did not check
for the potential failure of the effective group ID change system
call. If the group ID change failed, a remote FTP user could use this
flaw to gain unauthorized read or write access to files that are owned
by the root group. (CVE-2011-1526)

This update also fixes the following bugs :

  - Due to a mistake in the Kerberos libraries, a client
    could fail to contact a Key Distribution Center (KDC) or
    terminate unexpectedly if the client had already more
    than 1024 file descriptors in use. This update backports
    modifications to the Kerberos libraries and the
    libraries use the poll() function instead of the
    select() function, as poll() does not have this
    limitation.

  - The KDC failed to release memory when processing a TGS
    (ticket-granting server) request from a client if the
    client request included an authenticator with a subkey.
    As a result, the KDC consumed an excessive amount of
    memory. With this update, the code releasing the memory
    has been added and the problem no longer occurs.

  - Under certain circumstances, if services requiring
    Kerberos authentication sent two authentication requests
    to the authenticating server, the second authentication
    request was flagged as a replay attack. As a result, the
    second authentication attempt was denied. This update
    applies an upstream patch that fixes this bug.

  - Previously, if Kerberos credentials had expired, the
    klist command could terminate unexpectedly with a
    segmentation fault when invoked with the -s option. This
    happened when klist encountered and failed to process an
    entry with no realm name while scanning the credential
    cache. With this update, the underlying code has been
    modified and the command handles such entries correctly.

  - Due to a regression, multi-line FTP macros terminated
    prematurely with a segmentation fault. This occurred
    because the previously-added patch failed to properly
    support multi-line macros. This update restores the
    support for multi-line macros and the problem no longer
    occurs.

All users of krb5 are advised to upgrade to these updated packages,
which resolve these issues."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=3041
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?921fd86c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
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
if (rpm_check(release:"SL5", reference:"krb5-debuginfo-1.6.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-devel-1.6.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-libs-1.6.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-server-1.6.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-server-ldap-1.6.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-workstation-1.6.1-70.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-server / etc");
}
