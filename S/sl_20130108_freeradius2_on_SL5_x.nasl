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
  script_id(63593);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-4966");

  script_name(english:"Scientific Linux Security Update : freeradius2 on SL5.x i386/x86_64 (20130108)");
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
"It was found that the 'unix' module ignored the password expiration
setting in '/etc/shadow'. If FreeRADIUS was configured to use this
module for user authentication, this flaw could allow users with an
expired password to successfully authenticate, even though their
access should have been denied. (CVE-2011-4966)

This update also fixes the following bugs :

  - After log rotation, the freeradius logrotate script
    failed to reload the radiusd daemon and log messages
    were lost. This update has added a command to the
    freeradius logrotate script to reload the radiusd daemon
    and the radiusd daemon re-initializes and reopens its
    log files after log rotation as expected.

  - The radtest script with the 'eap-md5' option failed
    because it passed the IP family argument when invoking
    the radeapclient utility and the radeapclient utility
    did not recognize the IP family. The radeapclient
    utility now recognizes the IP family argument and
    radtest now works with eap-md5 as expected.

  - Previously, freeradius was compiled without the
    '--with-udpfromto' option. Consequently, with a
    multihomed server and explicitly specifying the IP
    address, freeradius sent the reply with the wrong IP
    source address. With this update, freeradius has been
    built with the '--with-udpfromto' configuration option
    and the RADIUS reply is always sourced from the IP
    address the request was sent to.

  - Due to invalid syntax in the PostgreSQL admin schema
    file, the FreeRADIUS PostgreSQL tables failed to be
    created. With this update, the syntax has been adjusted
    and the tables are created as expected.

  - FreeRADIUS has a thread pool that dynamically grows
    based on load. If multiple threads using the
    'rlm_perl()' function are spawned in quick succession,
    the FreeRADIUS server sometimes terminated unexpectedly
    with a segmentation fault due to parallel calls to the
    'rlm_perl_clone()' function. With this update, a mutex
    for the threads has been added and the problem no longer
    occurs.

  - The man page for 'rlm_dbm_parser' was incorrectly
    installed as 'rlm_dbm_parse', omitting the trailing 'r'.
    The man page now correctly appears as rlm_dbm_parser.

They are also advised to check for RPM backup files ending in
'.rpmnew' or '.rpmsave' under the /etc/raddb/ directory after the
update because the FreeRADIUS server will attempt to load every file
it finds in its configuration directory. The extra files will often
cause the wrong configuration values to be applied resulting in either
unpredictable behavior or the failure of the server to initialize and
run."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=1952
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?261dadd1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeradius2-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"freeradius2-2.1.12-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"freeradius2-debuginfo-2.1.12-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"freeradius2-krb5-2.1.12-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"freeradius2-ldap-2.1.12-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"freeradius2-mysql-2.1.12-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"freeradius2-perl-2.1.12-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"freeradius2-postgresql-2.1.12-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"freeradius2-python-2.1.12-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"freeradius2-unixODBC-2.1.12-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"freeradius2-utils-2.1.12-5.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius2 / freeradius2-debuginfo / freeradius2-krb5 / etc");
}
