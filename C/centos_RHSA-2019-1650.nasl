#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1650 and 
# CentOS Errata and Security Advisory 2019:1650 respectively.
#

include("compat.inc");

if (description)
{
  script_id(126479);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/08");

  script_cve_id("CVE-2019-9824");
  script_xref(name:"RHSA", value:"2019:1650");

  script_name(english:"CentOS 6 : qemu-kvm (CESA-2019:1650)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for qemu-kvm is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

Kernel-based Virtual Machine (KVM) is a full virtualization solution
for Linux on a variety of architectures. The qemu-kvm packages provide
the user-space component for running virtual machines that use KVM.

Security Fix(es) :

* QEMU: Slirp: information leakage in tcp_emu() due to uninitialized
stack variables (CVE-2019-9824)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-July/023350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd4fdc0a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9824");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"qemu-guest-agent-0.12.1.2-2.506.el6_10.4")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.506.el6_10.4")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.506.el6_10.4")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.506.el6_10.4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-guest-agent / qemu-img / qemu-kvm / qemu-kvm-tools");
}
