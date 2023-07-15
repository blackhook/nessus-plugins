#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1889 and 
# CentOS Errata and Security Advisory 2015:1889 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86483);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-5260", "CVE-2015-5261");
  script_xref(name:"RHSA", value:"2015:1889");

  script_name(english:"CentOS 6 : spice-server (CESA-2015:1889)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated spice-server package that fixes two security issues is now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display protocol for virtual environments. SPICE users can
access a virtualized desktop or server from the local system or any
system with network access to the server. SPICE is used in Red Hat
Enterprise Linux for viewing virtualized guests running on the
Kernel-based Virtual Machine (KVM) hypervisor or on Red Hat Enterprise
Virtualization Hypervisors.

A heap-based buffer overflow flaw was found in the way SPICE handled
certain guest QXL commands related to surface creation. A user in a
guest could use this flaw to read and write arbitrary memory locations
on the host. (CVE-2015-5261)

A heap-based buffer overflow flaw was found in the way spice handled
certain QXL commands related to the 'surface_id' parameter. A user in
a guest could use this flaw to crash the host QEMU-KVM process or,
possibly, execute arbitrary code with the privileges of the host
QEMU-KVM process. (CVE-2015-5260)

These issues were discovered by Frediano Ziglio of Red Hat.

All spice-server users are advised to upgrade to this updated package,
which contains backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-October/021428.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?293b6c67"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5260");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"spice-server-0.12.4-12.el6_7.3")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"spice-server-devel-0.12.4-12.el6_7.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-server / spice-server-devel");
}
