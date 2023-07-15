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
  script_id(63602);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-3417");

  script_name(english:"Scientific Linux Security Update : quota on SL5.x i386/x86_64 (20130108)");
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
"It was discovered that the rpc.rquotad service did not use
tcp_wrappers correctly. Certain hosts access rules defined in
'/etc/hosts.allow' and '/etc/hosts.deny' may not have been honored,
possibly allowing remote attackers to bypass intended access
restrictions. (CVE-2012-3417)

This update also fixes the following bugs :

  - Prior to this update, values were not properly
    transported via the remote procedure call (RPC) and
    interpreted by the client when querying the quota usage
    or limits for network-mounted file systems if the quota
    values were 2^32 kilobytes or greater. As a consequence,
    the client reported mangled values. This update modifies
    the underlying code so that such values are correctly
    interpreted by the client.

  - Prior to this update, warnquota sent messages about
    exceeded quota limits from a valid domain name if the
    warnquota tool was enabled to send warning e-mails and
    the superuser did not change the default warnquota
    configuration. As a consequence, the recipient could
    reply to invalid addresses. This update modifies the
    default warnquota configuration to use the reserved
    example.com. domain. Now, warnings about exceeded quota
    limits are sent from the reserved domain that inform the
    superuser to change to the correct value.

  - Previously, quota utilities could not recognize the file
    system as having quotas enabled and refused to operate
    on it due to incorrect updating of /etc/mtab. This
    update prefers /proc/mounts to get a list of file
    systems with enabled quotas. Now, quota utilities
    recognize file systems with enabled quotas as expected.

  - Prior to this update, the setquota(8) tool on XFS file
    systems failed to set disk limits to values greater than
    2^31 kilobytes. This update modifies the integer
    conversion in the setquota(8) tool to use a 64-bit
    variable big enough to store such values."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=1090
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c53c20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quota and / or quota-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:quota");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:quota-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/13");
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
if (rpm_check(release:"SL5", reference:"quota-3.13-8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"quota-debuginfo-3.13-8.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quota / quota-debuginfo");
}
