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
  script_id(65977);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1897");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL6.x i386/x86_64 (20130415)");
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
"It was found that the 389 Directory Server did not properly restrict
access to entries when the 'nsslapd-allow-anonymous-access'
configuration setting was set to 'rootdse'. An anonymous user could
connect to the LDAP database and, if the search scope is set to BASE,
obtain access to information outside of the rootDSE. (CVE-2013-1897)

This update also fixes the following bugs :

  - Previously, the schema-reload plug-in was not
    thread-safe. Consequently, executing the
    schema-reload.pl script under heavy load could have
    caused the ns-slapd process to terminate unexpectedly
    with a segmentation fault. Currently, the schema-reload
    plug-in is re-designed so that it is thread- safe, and
    the schema-reload.pl script can be executed along with
    other LDAP operations.

  - An out of scope problem for a local variable, in some
    cases, caused the modrdn operation to terminate
    unexpectedly with a segmentation fault. This update
    declares the local variable at the proper place of the
    function so it does not go out of scope, and the modrdn
    operation no longer crashes.

  - A task manually constructed an exact value to be removed
    from the configuration if the 'replica-force-cleaning'
    option was used. Consequently, the task configuration
    was not cleaned up, and every time the server was
    restarted, the task behaved in the described manner.
    This update searches the configuration for the exact
    value to delete, instead of manually building the value,
    and the task does not restart when the server is
    restarted.

  - Previously, a NULL pointer dereference could have
    occurred when attempting to get effective rights on an
    entry that did not exist, leading to an unexpected
    termination due to a segmentation fault. This update
    checks for NULL entry pointers and returns the
    appropriate error. Now, attempts to get effective rights
    on an entry that does not exist no longer causes
    crashes, and the server returns the appropriate error
    message.

  - A problem in the lock timing in the DNA plug-in caused a
    deadlock if the DNA operation was executed with other
    plug-ins. This update moves the release timing of the
    problematic lock, and the DNA plug-in does not cause the
    deadlock.

After installing this update, the 389 server service will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1304&L=scientific-linux-errata&T=0&P=954
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9a5290f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/16");
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


flag = 0;
if (rpm_check(release:"SL6", reference:"389-ds-base-1.2.11.15-14.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-debuginfo-1.2.11.15-14.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-devel-1.2.11.15-14.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-libs-1.2.11.15-14.el6_4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
}
