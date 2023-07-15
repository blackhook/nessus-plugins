#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0101. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20732);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2002-2185", "CVE-2004-1190", "CVE-2005-2458", "CVE-2005-2709", "CVE-2005-2800", "CVE-2005-3044", "CVE-2005-3106", "CVE-2005-3109", "CVE-2005-3276", "CVE-2005-3356", "CVE-2005-3358", "CVE-2005-3784", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4605");
  script_xref(name:"RHSA", value:"2006:0101");

  script_name(english:"RHEL 4 : kernel (RHSA-2006:0101)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues in the Red
Hat Enterprise Linux 4 kernel are now available.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

  - a flaw in network IGMP processing that a allowed a
    remote user on the local network to cause a denial of
    service (disabling of multicast reports) if the system
    is running multicast applications (CVE-2002-2185,
    moderate)

  - a flaw which allowed a local user to write to firmware
    on read-only opened /dev/cdrom devices (CVE-2004-1190,
    moderate)

  - a flaw in gzip/zlib handling internal to the kernel that
    may allow a local user to cause a denial of service
    (crash) (CVE-2005-2458, low)

  - a flaw in procfs handling during unloading of modules
    that allowed a local user to cause a denial of service
    or potentially gain privileges (CVE-2005-2709, moderate)

  - a flaw in the SCSI procfs interface that allowed a local
    user to cause a denial of service (crash)
    (CVE-2005-2800, moderate)

  - a flaw in 32-bit-compat handling of the TIOCGDEV ioctl
    that allowed a local user to cause a denial of service
    (crash) (CVE-2005-3044, important)

  - a race condition when threads share memory mapping that
    allowed local users to cause a denial of service
    (deadlock) (CVE-2005-3106, important)

  - a flaw when trying to mount a non-hfsplus filesystem
    using hfsplus that allowed local users to cause a denial
    of service (crash) (CVE-2005-3109, moderate)

  - a minor info leak with the get_thread_area() syscall
    that allowed a local user to view uninitialized kernel
    stack data (CVE-2005-3276, low)

  - a flaw in mq_open system call that allowed a local user
    to cause a denial of service (crash) (CVE-2005-3356,
    important)

  - a flaw in set_mempolicy that allowed a local user on
    some 64-bit architectures to cause a denial of service
    (crash) (CVE-2005-3358, important)

  - a flaw in the auto-reap of child processes that allowed
    a local user to cause a denial of service (crash)
    (CVE-2005-3784, important)

  - a flaw in the IPv6 flowlabel code that allowed a local
    user to cause a denial of service (crash)
    (CVE-2005-3806, important)

  - a flaw in network ICMP processing that allowed a local
    user to cause a denial of service (memory exhaustion)
    (CVE-2005-3848, important)

  - a flaw in file lease time-out handling that allowed a
    local user to cause a denial of service (log file
    overflow) (CVE-2005-3857, moderate)

  - a flaw in network IPv6 xfrm handling that allowed a
    local user to cause a denial of service (memory
    exhaustion) (CVE-2005-3858, important)

  - a flaw in procfs handling that allowed a local user to
    read kernel memory (CVE-2005-4605, important)

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2002-2185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-4605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2006:0101"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  cve_list = make_list("CVE-2002-2185", "CVE-2004-1190", "CVE-2005-2458", "CVE-2005-2709", "CVE-2005-2800", "CVE-2005-3044", "CVE-2005-3106", "CVE-2005-3109", "CVE-2005-3276", "CVE-2005-3356", "CVE-2005-3358", "CVE-2005-3784", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4605");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2006:0101");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0101";
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-22.0.2.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-22.0.2.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-22.0.2.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-22.0.2.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-22.0.2.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-22.0.2.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-22.0.2.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-22.0.2.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-22.0.2.EL")) flag++;

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
