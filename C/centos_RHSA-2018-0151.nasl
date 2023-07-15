#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0151 and 
# CentOS Errata and Security Advisory 2018:0151 respectively.
#

include("compat.inc");

if (description)
{
  script_id(106353);
  script_version("3.10");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2015-8539", "CVE-2017-12192", "CVE-2017-12193", "CVE-2017-15649", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2017-7472");
  script_xref(name:"RHSA", value:"2018:0151");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"CentOS 7 : kernel (CESA-2018:0151) (Meltdown) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of instructions (a
commonly used performance optimization). There are three primary
variants of the issue which differ in the way the speculative
execution can be exploited.

Note: This issue is present in hardware and cannot be fully fixed via
software update. The updated kernel packages provide software
mitigation for this hardware issue at a cost of potential performance
penalty. Please refer to References section for further information
about this issue and the performance impact.

In this update initial mitigations for IBM Power (PowerPC) and IBM
zSeries (S390) architectures are provided.

* Variant CVE-2017-5715 triggers the speculative execution by
utilizing branch target injection. It relies on the presence of a
precisely-defined instruction sequence in the privileged code as well
as the fact that memory accesses may cause allocation into the
microprocessor's data cache even for speculatively executed
instructions that never actually commit (retire). As a result, an
unprivileged attacker could use this flaw to cross the syscall and
guest/host boundaries and read privileged memory by conducting
targeted cache side-channel attacks. This fix specifically addresses
S390 processors. (CVE-2017-5715, Important)

* Variant CVE-2017-5753 triggers the speculative execution by
performing a bounds-check bypass. It relies on the presence of a
precisely-defined instruction sequence in the privileged code as well
as the fact that memory accesses may cause allocation into the
microprocessor's data cache even for speculatively executed
instructions that never actually commit (retire). As a result, an
unprivileged attacker could use this flaw to cross the syscall
boundary and read privileged memory by conducting targeted cache
side-channel attacks. This fix specifically addresses S390 and PowerPC
processors. (CVE-2017-5753, Important)

* Variant CVE-2017-5754 relies on the fact that, on impacted
microprocessors, during speculative execution of instruction
permission faults, exception generation triggered by a faulting access
is suppressed until the retirement of the whole instruction block. In
a combination with the fact that memory accesses may populate the
cache even when the block is being dropped and never committed
(executed), an unprivileged local attacker could use this flaw to read
privileged (kernel space) memory by conducting targeted cache
side-channel attacks. Note: CVE-2017-5754 affects Intel x86-64
microprocessors. AMD x86-64 microprocessors are not affected by this
issue. This fix specifically addresses PowerPC processors.
(CVE-2017-5754, Important)

Red Hat would like to thank Google Project Zero for reporting
CVE-2017-5715, CVE-2017-5753, and CVE-2017-5754.

This update also fixes the following security issues and bugs :

Space precludes documenting all of the bug fixes and enhancements
included in this advisory. To see the complete list of bug fixes and
enhancements, refer to the following KnowledgeBase article:
https://access.redhat.com/articles/ 3327131."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-January/022730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe6db376"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8539");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-693.17.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-693.17.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / kernel-debug-devel / etc");
}
