#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1474 and 
# CentOS Errata and Security Advisory 2013:1474 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70686);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-4282");
  script_xref(name:"RHSA", value:"2013:1474");

  script_name(english:"CentOS 5 : qspice (CESA-2013:1474)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qspice packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display protocol for virtual environments. SPICE users can
access a virtualized desktop or server from the local system or any
system with network access to the server. SPICE is used in Red Hat
Enterprise Linux for viewing virtualized guests running on the
Kernel-based Virtual Machine (KVM) hypervisor or on Red Hat Enterprise
Virtualization Hypervisors.

A stack-based buffer overflow flaw was found in the way the
reds_handle_ticket() function in the spice-server library handled
decryption of ticket data provided by the client. A remote user able
to initiate a SPICE connection to an application acting as a SPICE
server could use this flaw to crash the application. (CVE-2013-4282)

This issue was discovered by Tomas Jamrisko of Red Hat.

All qspice users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-October/019994.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?087d8a1d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qspice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4282");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qspice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qspice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qspice-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"qspice-0.3.0-56.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"qspice-libs-0.3.0-56.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"qspice-libs-devel-0.3.0-56.el5_10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qspice / qspice-libs / qspice-libs-devel");
}
