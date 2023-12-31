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
  script_id(60717);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-4567", "CVE-2009-4536", "CVE-2009-4537", "CVE-2009-4538");

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
"CVE-2007-4567 kernel: ipv6_hop_jumbo remote system crash

CVE-2009-4537 kernel: r8169 issue reported at 26c3

CVE-2009-4538 kernel: e1000e frame fragment issue

CVE-2009-4536 kernel: e1000 issue reported at 26c3

This update fixes the following security issues :

  - a flaw was found in the IPv6 Extension Header (EH)
    handling implementation in the Linux kernel. The
    skb->dst data structure was not properly validated in
    the ipv6_hop_jumbo() function. This could possibly lead
    to a remote denial of service. (CVE-2007-4567,
    Important)

  - a flaw was found in each of the following Intel PRO/1000
    Linux drivers in the Linux kernel: e1000 and e1000e. A
    remote attacker using packets larger than the MTU could
    bypass the existing fragment check, resulting in
    partial, invalid frames being passed to the network
    stack. These flaws could also possibly be used to
    trigger a remote denial of service. (CVE-2009-4536,
    CVE-2009-4538, Important)

  - a flaw was found in the Realtek r8169 Ethernet driver in
    the Linux kernel. Receiving overly-long frames with
    network cards supported by this driver could possibly
    result in a remote denial of service. (CVE-2009-4537,
    Important)

The system must be rebooted for this update to take effect.

Note1: Due to the fuse kernel module now being part of the kernel, we
are updating fuse on the older releases to match the fuse that was
released by The Upstream Vendor.

Note2: xfs is now part of the kernel in x86_64. Because of this there
is no kernel-module-xfs for x86_64.

Note3: ipw3945 support has been changed to iwlwifi3945 in SL 54, and
is in the kernel. Because of this there is no kernel-module-ipw3945
for SL54.

Note4: Support for the Atheros chipset in now in the kernel. We are
not sure if the infrastructure is in place for SL 50-53, so we are
still providing the madwifi kernel modules for SL 50-53."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1001&L=scientific-linux-errata&T=0&P=699
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0122c19d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/07");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-164.10.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-164.10.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-164.10.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-164.10.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-164.10.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-164.10.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-164.10.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-164.10.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-164.10.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-164.10.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
