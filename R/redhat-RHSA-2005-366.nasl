#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:366. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18095);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-0135", "CVE-2005-0207", "CVE-2005-0209", "CVE-2005-0210", "CVE-2005-0384", "CVE-2005-0400", "CVE-2005-0449", "CVE-2005-0529", "CVE-2005-0530", "CVE-2005-0531", "CVE-2005-0736", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0767", "CVE-2005-0815", "CVE-2005-0839", "CVE-2005-0867", "CVE-2005-0977", "CVE-2005-1041");
  script_xref(name:"RHSA", value:"2005:366");

  script_name(english:"RHEL 4 : kernel (RHSA-2005:366)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 9 August 2005] The advisory text has been updated to show
that this update fixed the security issue named CVE-2005-0210 but not
CVE-2005-0209. The issue CVE-2005-0209 was actually fixed by
RHSA-2005:420. No changes have been made to the packages associated
with this advisory.

The Linux kernel handles the basic functions of the operating system.

A flaw in the fib_seq_start function was discovered. A local user
could use this flaw to cause a denial of service (system crash) via
/proc/net/route. (CVE-2005-1041)

A flaw in the tmpfs file system was discovered. A local user could use
this flaw to cause a denial of service (system crash). (CVE-2005-0977)

An integer overflow flaw was found when writing to a sysfs file. A
local user could use this flaw to overwrite kernel memory, causing a
denial of service (system crash) or arbitrary code execution.
(CVE-2005-0867)

Keith Owens reported a flaw in the Itanium unw_unwind_to_user
function. A local user could use this flaw to cause a denial of
service (system crash) on Itanium architectures. (CVE-2005-0135)

A flaw in the NFS client O_DIRECT error case handling was discovered.
A local user could use this flaw to cause a denial of service (system
crash). (CVE-2005-0207)

A small memory leak when defragmenting local packets was discovered
that affected the Linux 2.6 kernel netfilter subsystem. A local user
could send a large number of carefully crafted fragments leading to
memory exhaustion (CVE-2005-0210)

A flaw was discovered in the Linux PPP driver. On systems allowing
remote users to connect to a server using ppp, a remote client could
cause a denial of service (system crash). (CVE-2005-0384)

A flaw was discovered in the ext2 file system code. When a new
directory is created, the ext2 block written to disk is not
initialized, which could lead to an information leak if a disk image
is made available to unprivileged users. (CVE-2005-0400)

A flaw in fragment queuing was discovered that affected the Linux
kernel netfilter subsystem. On systems configured to filter or process
network packets (e.g. firewalling), a remote attacker could send a
carefully crafted set of fragmented packets to a machine and cause a
denial of service (system crash). In order to sucessfully exploit this
flaw, the attacker would need to know or guess some aspects of the
firewall ruleset on the target system. (CVE-2005-0449)

A number of flaws were found in the Linux 2.6 kernel. A local user
could use these flaws to read kernel memory or cause a denial of
service (crash). (CVE-2005-0529, CVE-2005-0530, CVE-2005-0531)

An integer overflow in sys_epoll_wait in eventpoll.c was discovered. A
local user could use this flaw to overwrite low kernel memory. This
memory is usually unused, not usually resulting in a security
consequence. (CVE-2005-0736)

A flaw when freeing a pointer in load_elf_library was discovered. A
local user could potentially use this flaw to cause a denial of
service (crash). (CVE-2005-0749)

A flaw was discovered in the bluetooth driver system. On systems where
the bluetooth modules are loaded, a local user could use this flaw to
gain elevated (root) privileges. (CVE-2005-0750)

A race condition was discovered that affected the Radeon DRI driver. A
local user who has DRI privileges on a Radeon graphics card may be
able to use this flaw to gain root privileges. (CVE-2005-0767)

Multiple range checking flaws were discovered in the iso9660 file
system handler. An attacker could create a malicious file system image
which would cause a denial or service or potentially execute arbitrary
code if mounted. (CVE-2005-0815)

A flaw was discovered when setting line discipline on a serial tty. A
local user may be able to use this flaw to inject mouse movements or
keystrokes when another user is logged in. (CVE-2005-0839)

Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
to the packages associated with their machine architectures and
configurations as listed in this erratum.

Please note that"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-1041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2005:366"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CAN-2005-0135", "CAN-2005-0207", "CAN-2005-0209", "CAN-2005-0210", "CAN-2005-0384", "CAN-2005-0400", "CAN-2005-0449", "CAN-2005-0529", "CAN-2005-0530", "CAN-2005-0531", "CAN-2005-0736", "CAN-2005-0749", "CAN-2005-0750", "CAN-2005-0767", "CAN-2005-0815", "CAN-2005-0839", "CAN-2005-0867", "CAN-2005-0977", "CAN-2005-1041", "CVE-2005-0135", "CVE-2005-0207", "CVE-2005-0209", "CVE-2005-0210", "CVE-2005-0384", "CVE-2005-0400", "CVE-2005-0449", "CVE-2005-0529", "CVE-2005-0530", "CVE-2005-0531", "CVE-2005-0736", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0767", "CVE-2005-0815", "CVE-2005-0839", "CVE-2005-0867", "CVE-2005-0977", "CVE-2005-1041");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2005:366");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:366";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-5.0.5.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-5.0.5.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-5.0.5.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-5.0.5.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-5.0.5.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-5.0.5.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-5.0.5.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-5.0.5.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-5.0.5.EL")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
  }
}
