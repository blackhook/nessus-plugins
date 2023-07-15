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
  script_id(62218);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2145");

  script_name(english:"Scientific Linux Security Update : qpid on SL6.x i386/x86_64 (20120919)");
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
"Apache Qpid is a reliable, cross-platform, asynchronous messaging
system that supports the Advanced Message Queuing Protocol (AMQP) in
several common programming languages.

It was discovered that the Qpid daemon (qpidd) did not allow the
number of connections from clients to be restricted. A malicious
client could use this flaw to open an excessive amount of connections,
preventing other legitimate clients from establishing a connection to
qpidd. (CVE-2012-2145)

To address CVE-2012-2145, new qpidd configuration options were
introduced: max-negotiate-time defines the time during which initial
protocol negotiation must succeed, connection-limit-per-user and
connection-limit-per-ip can be used to limit the number of connections
per user and client host IP. Refer to the qpidd manual page for
additional details.

In addition, the qpid-cpp, qpid-qmf, qpid-tools, and python-qpid
packages have been upgraded to upstream version 0.14, which provides a
number of bug fixes and enhancements over the previous version.

All users of qpid are advised to upgrade to these updated packages,
which fix these issues and add these enhancements.

For dependency resolution saslwrapper, saslwrapper-devel,
python-saslwrapper, and ruby-saslwrapper have been added to this
update"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=3414
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cb33b07"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qpid-cpp-client-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qpid-cpp-server-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qpid-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/21");
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
if (rpm_check(release:"SL6", reference:"python-qpid-0.14-11.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"python-qpid-qmf-0.14-14.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-cpp-client-0.14-22.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-cpp-client-ssl-0.14-22.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-cpp-server-0.14-22.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-cpp-server-ssl-0.14-22.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-qmf-0.14-14.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-tools-0.14-6.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-qpid-qmf-0.14-14.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-qpid / python-qpid-qmf / qpid-cpp-client / etc");
}
