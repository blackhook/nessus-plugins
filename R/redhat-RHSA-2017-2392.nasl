#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2392. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102158);
  script_version("3.10");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-10155", "CVE-2016-4020", "CVE-2016-6835", "CVE-2016-6888", "CVE-2016-7422", "CVE-2016-7466", "CVE-2016-8576", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-2630", "CVE-2017-5579", "CVE-2017-5898", "CVE-2017-5973", "CVE-2017-9310", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9375");
  script_xref(name:"RHSA", value:"2017:2392");

  script_name(english:"RHEL 7 : qemu-kvm-rhev (RHSA-2017:2392)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for qemu-kvm-rhev is now available for RHEV 4.X RHEV-H and
Agents for RHEL 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on a variety of architectures. The qemu-kvm-rhev packages
provide the user-space component for running virtual machines that use
KVM in environments managed by Red Hat products.

The following packages have been upgraded to a later upstream version:
qemu-kvm-rhev (2.9.0). (BZ#1387372, BZ#1387600, BZ#1400962)

Security Fix(es) :

* A stack-based buffer overflow flaw was found in the Quick Emulator
(QEMU) built with the Network Block Device (NBD) client support. The
flaw could occur while processing server's response to a
'NBD_OPT_LIST' request. A malicious NBD server could use this issue to
crash a remote NBD client resulting in DoS or potentially execute
arbitrary code on client host with privileges of the QEMU process.
(CVE-2017-2630)

* An integer overflow flaw was found in Quick Emulator (QEMU) in the
CCID Card device support. The flaw could occur while passing messages
via command/response packets to and from the host. A privileged user
inside a guest could use this flaw to crash the QEMU process.
(CVE-2017-5898)

* An information exposure flaw was found in Quick Emulator (QEMU) in
Task Priority Register (TPR) optimizations for 32-bit Windows guests.
The flaw could occur while accessing TPR. A privileged user inside a
guest could use this issue to read portions of the host memory.
(CVE-2016-4020)

* A memory-leak flaw was found in the Quick Emulator(QEMU) built with
USB xHCI controller emulation support. The flaw could occur while
doing a USB-device unplug operation. Unplugging the device repeatedly
resulted in leaking host memory, affecting other services on the host.
A privileged user inside the guest could exploit this flaw to cause a
denial of service on the host or potentially crash the host's QEMU
process instance. (CVE-2016-7466)

* Multiple CVEs(CVE-2016-10155, CVE-2016-4020, CVE-2016-6835,
CVE-2016-6888, CVE-2016-7422, CVE-2016-7466, CVE-2016-8576,
CVE-2016-8669, CVE-2016-8909, CVE-2016-8910, CVE-2016-9907,
CVE-2016-9911, CVE-2016-9921, CVE-2016-9922, CVE-2017-2630,
CVE-2017-5579, CVE-2017-5898, CVE-2017-5973, CVE-2017-9310,
CVE-2017-9373, CVE-2017-9374, CVE-2017-9375) were fixed as result of
rebase to QEMU version 2.9.0.

Red Hat would like to thank Li Qiang (Qihoo 360 Inc.) for reporting
CVE-2016-6835 and CVE-2016-6888; Li Qiang (360.cn Inc.) for reporting
CVE-2017-5898, CVE-2016-7466, CVE-2016-10155, CVE-2017-5579, and
CVE-2017-5973; Donghai Zdh (Alibaba Inc.) for reporting CVE-2016-4020;
Qinghao Tang (Marvel Team 360.cn Inc.) and Zhenhao Hong (Marvel Team
360.cn Inc.) for reporting CVE-2016-7422; PSIRT (Huawei Inc.) for
reporting CVE-2016-8669; Andrew Henderson (Intelligent Automation
Inc.) for reporting CVE-2016-8910; Qinghao Tang (Qihoo 360), Li Qiang
(Qihoo 360), and Jiangxin (Huawei Inc.) for reporting CVE-2016-9921
and CVE-2016-9922; and Li Qiang (Qihoo 360 Gear Team) for reporting
CVE-2017-9310, CVE-2017-9373, CVE-2017-9374, and CVE-2017-9375.

Additional Changes :

This update also fixes several bugs and adds various enhancements.
Documentation for these changes is available from the Release Notes
document linked to in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9375"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools-rhev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2392";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-img-rhev-2.9.0-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-common-rhev-2.9.0-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-rhev-2.9.0-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-rhev-debuginfo-2.9.0-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-tools-rhev-2.9.0-14.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img-rhev / qemu-kvm-common-rhev / qemu-kvm-rhev / etc");
  }
}
