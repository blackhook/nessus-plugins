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
  script_id(60965);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4243");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
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
"This update fixes the following security issues :

  - A divide-by-zero flaw was found in the
    tcp_select_initial_window() function in the Linux
    kernel's TCP/IP protocol suite implementation. A local,
    unprivileged user could use this flaw to trigger a
    denial of service by calling setsockopt() with certain
    options. (CVE-2010-4165, Moderate)

  - A use-after-free flaw in the mprotect() system call in
    the Linux kernel could allow a local, unprivileged user
    to cause a local denial of service. (CVE-2010-4169,
    Moderate)

  - A flaw was found in the Linux kernel execve() system
    call implementation. A local, unprivileged user could
    cause large amounts of memory to be allocated but not
    visible to the OOM (Out of Memory) killer, triggering a
    denial of service. (CVE-2010-4243, Moderate)

This update also fixes several bugs and adds two enhancements.

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=1215
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c539730"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/22");
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
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-71.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-71.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-71.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-71.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-71.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-71.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-71.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-71.18.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
