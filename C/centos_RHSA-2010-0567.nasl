#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0567 and 
# CentOS Errata and Security Advisory 2010:0567 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47903);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-2526");
  script_xref(name:"RHSA", value:"2010:0567");

  script_name(english:"CentOS 5 : lvm2-cluster (CESA-2010:0567)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated lvm2-cluster package that fixes one security issue is now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The lvm2-cluster package contains support for Logical Volume
Management (LVM) in a clustered environment.

It was discovered that the cluster logical volume manager daemon
(clvmd) did not verify the credentials of clients connecting to its
control UNIX abstract socket, allowing local, unprivileged users to
send control commands that were intended to only be available to the
privileged root user. This could allow a local, unprivileged user to
cause clvmd to exit, or request clvmd to activate, deactivate, or
reload any logical volume on the local system or another system in the
cluster. (CVE-2010-2526)

Note: This update changes clvmd to use a pathname-based socket rather
than an abstract socket. As such, the lvm2 update RHBA-2010:0569,
which changes LVM to also use this pathname-based socket, must also be
installed for LVM to be able to communicate with the updated clvmd.

All lvm2-cluster users should upgrade to this updated package, which
contains a backported patch to correct this issue. After installing
the updated package, clvmd must be restarted for the update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016844.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18b4f653"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016845.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33dc4eb5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lvm2-cluster package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lvm2-cluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"lvm2-cluster-2.02.56-7.el5_5.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lvm2-cluster");
}
