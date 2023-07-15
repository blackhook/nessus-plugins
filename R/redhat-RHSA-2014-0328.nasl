#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0328. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73198);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1860", "CVE-2013-7266", "CVE-2013-7270", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0101", "CVE-2014-2038");
  script_bugtraq_id(58510, 65588, 65943);
  script_xref(name:"RHSA", value:"2014:0328");

  script_name(english:"RHEL 6 : kernel (RHSA-2014:0328)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the get_rx_bufs() function in the
vhost_net implementation in the Linux kernel handled error conditions
reported by the vhost_get_vq_desc() function. A privileged guest user
could use this flaw to crash the host. (CVE-2014-0055, Important)

* A flaw was found in the way the Linux kernel processed an
authenticated COOKIE_ECHO chunk during the initialization of an SCTP
connection. A remote attacker could use this flaw to crash the system
by initiating a specially crafted SCTP handshake in order to trigger a
NULL pointer dereference on the system. (CVE-2014-0101, Important)

* A flaw was found in the way the Linux kernel's CIFS implementation
handled uncached write operations with specially crafted iovec
structures. An unprivileged local user with access to a CIFS share
could use this flaw to crash the system, leak kernel memory, or,
potentially, escalate their privileges on the system. Note: the
default cache settings for CIFS mounts on Red Hat Enterprise Linux 6
prohibit a successful exploitation of this issue. (CVE-2014-0069,
Moderate)

* A heap-based buffer overflow flaw was found in the Linux kernel's
cdc-wdm driver, used for USB CDC WCM device management. An attacker
with physical access to a system could use this flaw to cause a denial
of service or, potentially, escalate their privileges. (CVE-2013-1860,
Low)

Red Hat would like to thank Nokia Siemens Networks for reporting
CVE-2014-0101, and Al Viro for reporting CVE-2014-0069.

This update also fixes several bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-7266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-7270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2038"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  cve_list = make_list("CVE-2013-1860", "CVE-2013-7266", "CVE-2013-7270", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0101", "CVE-2014-2038");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2014:0328");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0328";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-abi-whitelists-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-devel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-devel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-headers-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-headers-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-431.11.2.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-431.11.2.el6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}