#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3522 and 
# CentOS Errata and Security Advisory 2018:3522 respectively.
#

include("compat.inc");

if (description)
{
  script_id(119049);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2017-7506");
  script_xref(name:"RHSA", value:"2018:3522");

  script_name(english:"CentOS 6 : spice-server (CESA-2018:3522)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for spice-server is now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display protocol for virtual environments. SPICE users can
access a virtualized desktop or server from the local system or any
system with network access to the server. SPICE is used in Red Hat
Enterprise Linux for viewing virtualized guests running on the
Kernel-based Virtual Machine (KVM) hypervisor or on Red Hat Enterprise
Virtualization Hypervisors.

Security Fix(es) :

* spice: Possible buffer overflow via invalid monitor configurations
(CVE-2017-7506)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

This issue was discovered by Frediano Ziglio (Red Hat)."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-November/023080.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d69b38d"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected spice-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7506");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"spice-server-0.12.4-16.el6_10.2")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"spice-server-devel-0.12.4-16.el6_10.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-server / spice-server-devel");
}
