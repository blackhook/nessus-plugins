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
  script_id(97415);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-2634", "CVE-2017-6074");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64 (20170224)");
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
"Security Fix(es) :

  - A use-after-free flaw was found in the way the Linux
    kernel's Datagram Congestion Control Protocol (DCCP)
    implementation freed SKB (socket buffer) resources for a
    DCCP_PKT_REQUEST packet when the IPV6_RECVPKTINFO option
    is set on the socket. A local, unprivileged user could
    use this flaw to alter the kernel memory, allowing them
    to escalate their privileges on the system.
    (CVE-2017-6074, Important)

  - It was found that the Linux kernel's Datagram Congestion
    Control Protocol (DCCP) implementation used the
    IPv4-only inet_sk_rebuild_header() function for both
    IPv4 and IPv6 DCCP connections, which could result in
    memory corruptions. A remote attacker could use this
    flaw to crash the system. (CVE-2017-2634, Moderate)

Important: This update disables the DCCP kernel module at load time by
using the kernel module blacklist method. The module is disabled in an
attempt to reduce further exposure to additional issues."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1702&L=scientific-linux-errata&F=&S=&P=5638
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3366f3c8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-419.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-419.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
}
