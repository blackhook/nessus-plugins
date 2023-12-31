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
  script_id(60967);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-4249", "CVE-2010-4251", "CVE-2010-4655");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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

  - A flaw was found in the Linux kernel's garbage collector
    for AF_UNIX sockets. A local, unprivileged user could
    use this flaw to trigger a denial of service
    (out-of-memory condition). (CVE-2010-4249, Moderate)

  - A flaw was found in the Linux kernel's networking
    subsystem. If the number of packets received exceeded
    the receiver's buffer limit, they were queued in a
    backlog, consuming memory, instead of being discarded. A
    remote attacker could abuse this flaw to cause a denial
    of service (out-of-memory condition). (CVE-2010-4251,
    Moderate)

  - A missing initialization flaw was found in the
    ethtool_get_regs() function in the Linux kernel's
    ethtool IOCTL handler. A local user who has the
    CAP_NET_ADMIN capability could use this flaw to cause an
    information leak. (CVE-2010-4655, Low)

This update also fixes several bugs.

The system must be rebooted for this update to take effect.

NOTE: For those who have tested our updated openafs package for SL5,
you will need to enable the sl-testing repository to properly do this
update. We apologize for this. yum --enablerepo=sl-testing update
kernel\* Again, this is only for those who have updated openafs to
1.4.14"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=7029
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b38a246d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-238.5.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
