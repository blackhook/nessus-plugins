#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0512. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108329);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/18");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_xref(name:"RHSA", value:"2018:0512");

  script_name(english:"RHEL 6 : kernel (RHSA-2018:0512) (Meltdown) (Spectre)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* hw: cpu: speculative execution branch target injection (s390-only)
(CVE-2017-5715, Important)

* hw: cpu: speculative execution bounds-check bypass (s390 and
powerpc) (CVE-2017-5753, Important)

* hw: cpu: speculative execution permission faults handling
(powerpc-only) (CVE-2017-5754)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fixes :

* If a fibre channel (FC) switch was powered down and then powered on
again, the SCSI device driver stopped permanently the SCSI device's
request queue. Consequently, the FC port login failed, leaving the
port state as 'Bypassed' instead of 'Online', and users had to reboot
the operating system. This update fixes the driver to avoid the
permanent stop of the request queue. As a result, SCSI device now
continues working as expected after power cycling the FC switch.
(BZ#1519857)

* Previously, on final close or unlink of a file, the find_get_pages()
function in the memory management sometimes found no pages even if
there were some pages left to save. Consequently, a kernel crash
occurred when attempting to enter the unlink() function. This update
fixes the find_get_pages() function in the memory management code to
not return 0 too early. As a result, the kernel no longer crashes due
to this behavior.(BZ# 1527811)

* Using IPsec connections under a heavy load could previously lead to
a network performance degradation, especially when using the
aesni-intel module. This update fixes the issue by making the cryptd
queue length configurable so that it can be increased to prevent an
overflow and packet drop. As a result, using IPsec under a heavy load
no longer reduces network performance. (BZ#1527802)

* Previously, a deadlock in the bnx2fc driver caused all adapters to
block and the SCSI error handler to become unresponsive. As a result,
data transferring through the adapter was sometimes blocked. This
update fixes bnx2fc, and data transferring through the adapter is no
longer blocked due to this behavior. (BZ#1523783)

* If an NFSv3 client mounted a subdirectory of an exported file
system, a directory entry to the mount hosting the export was
incorrectly held even after clearing the cache. Consequently, attempts
to unmount the subdirectory with the umount command failed with the
EBUSY error. With this update, the underlying source code has been
fixed, and the unmount operation now succeeds as expected in the
described situation. (BZ#1535938)

Users of kernel are advised to upgrade to these updated packages,
which fix these bugs. The system must be rebooted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5754"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2018:0512");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:0512";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-abi-whitelists-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-devel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-devel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-headers-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-headers-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-696.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-696.23.1.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
