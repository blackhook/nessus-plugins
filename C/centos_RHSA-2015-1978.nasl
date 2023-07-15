#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1978 and 
# CentOS Errata and Security Advisory 2015:1978 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86723);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-8559", "CVE-2015-5156");
  script_xref(name:"RHSA", value:"2015:1978");

  script_name(english:"CentOS 7 : kernel (CESA-2015:1978)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated kernel packages that fix two security issues, several bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's VFS subsystem handled
file system locks. A local, unprivileged user could use this flaw to
trigger a deadlock in the kernel, causing a denial of service on the
system. (CVE-2014-8559, Moderate)

* A buffer overflow flaw was found in the way the Linux kernel's
virtio-net subsystem handled certain fraglists when the GRO (Generic
Receive Offload) functionality was enabled in a bridged network
configuration. An attacker on the local network could potentially use
this flaw to crash the system, or, although unlikely, elevate their
privileges on the system. (CVE-2015-5156, Moderate)

The CVE-2015-5156 issue was discovered by Jason Wang of Red Hat.

This update also fixes several bugs and adds one enhancement. Refer to
the following Knowledgebase article for further information :

https://access.redhat.com/articles/2039563

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement. The system must be rebooted for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-November/021463.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?349e798d"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5156");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-229.20.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-229.20.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / kernel-debug-devel / etc");
}
