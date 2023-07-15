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
  script_id(84790);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-5321", "CVE-2015-1593", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3636");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20150714)");
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
"* A NULL pointer dereference flaw was found in the way the Linux
kernel's virtual console implementation handled reference counting
when accessing pseudo-terminal device files (/dev/pts/*). A local,
unprivileged attacker could use this flaw to crash the system.
(CVE-2011-5321, Moderate)

* It was found that the Linux kernel's ping socket implementation did
not properly handle socket unhashing during spurious disconnects,
which could lead to a use-after-free flaw. On x86-64 architecture
systems, a local user able to create ping sockets could use this flaw
to crash the system. On non-x86-64 architecture systems, a local user
able to create ping sockets could use this flaw to escalate their
privileges on the system. (CVE-2015-3636, Moderate)

* An integer overflow flaw was found in the way the Linux kernel
randomized the stack for processes on certain 64-bit architecture
systems, such as x86-64, causing the stack entropy to be reduced by
four. (CVE-2015-1593, Low)

* A flaw was found in the way the Linux kernel's 32-bit emulation
implementation handled forking or closing of a task with an 'int80'
entry. A local user could potentially use this flaw to escalate their
privileges on the system. (CVE-2015-2830, Low)

* It was found that the Linux kernel's TCP/IP protocol suite
implementation for IPv6 allowed the Hop Limit value to be set to a
smaller value than the default one. An attacker on a local network
could use this flaw to prevent systems on that network from sending or
receiving network packets. (CVE-2015-2922, Low)

For information on the most significant of these changes, users are
directed to the following article on the Red Hat Customer Portal :

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1507&L=scientific-linux-errata&F=&S=&P=7426
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17313eca"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-caps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-fips-aesni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"dracut-004-356.el6_6.3")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-caps-004-356.el6_6.3")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-fips-004-356.el6_6.3")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-fips-aesni-004-356.el6_6.3")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-generic-004-356.el6_6.3")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-kernel-004-356.el6_6.3")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-network-004-356.el6_6.3")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-tools-004-356.el6_6.3")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-504.30.3.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dracut / dracut-caps / dracut-fips / dracut-fips-aesni / etc");
}
