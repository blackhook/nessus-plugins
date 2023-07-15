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
  script_id(73454);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0159");

  script_name(english:"Scientific Linux Security Update : openafs on SL5.x, SL6.x i386/x86_64 (20140411)");
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
"An attacker with the ability to connect to an OpenAFS fileserver can
trigger a buffer overflow, crashing the server.

The GetStatistics64 remote procedure call (RPC) was introduced in
OpenAFS 1.4.8 as part of the support for fileserver partitions larger
than 2 TiB. The GetStatistics64 RPC is used by remote administrative
programs to retrieve statistical information about fileservers. The
GetStatistics64 RPC requests do not require authentication.

A bug has been discovered in the GetStatistics64 RPC which can trigger
a fileserver crash. The version argument of the GetStatistics64 RPC is
used to determine how much memory is allocated for the RPC reply.
However the range of this argument is not validated, allowing an
attacker to cause insufficient memory to be allocated for the
statistical information reply buffer.

Clients are not affected."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1404&L=scientific-linux-errata&T=0&P=813
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f08f979"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.21.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.21.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.21.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-431");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-module-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-plumbing-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/10");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.21.1.el5-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-348.21.1.el5PAE-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.21.1.el5xen-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-devel-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-client-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-compat-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debug-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-devel-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kernel-source-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kpasswd-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-krb5-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-server-1.4.15-84.sl5")) flag++;

if (rpm_check(release:"SL6", reference:"kmod-openafs-431-1.6.5.1-148.sl6.431.11.2")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-devel-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-client-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-compat-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-devel-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kernel-source-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kpasswd-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-krb5-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-module-tools-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-plumbing-tools-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-server-1.6.5.1-148.sl6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-module-openafs-2.6.18-348.21.1.el5 / etc");
}
