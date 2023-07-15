#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:2732 and 
# Oracle Linux Security Advisory ELSA-2018-2732 respectively.
#

include("compat.inc");

if (description)
{
  script_id(117624);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2018-10873");
  script_xref(name:"RHSA", value:"2018:2732");

  script_name(english:"Oracle Linux 6 : spice-gtk / spice-server (ELSA-2018-2732)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:2732 :

An update for spice-gtk and spice-server is now available for Red Hat
Enterprise Linux 6.

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

The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for Simple
Protocol for Independent Computing Environments (SPICE) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of
this widget to access virtual machines using the SPICE protocol.

Security Fix(es) :

* spice: Missing check in demarshal.py:write_validate_array_item()
allows for buffer overflow and denial of service (CVE-2018-10873)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

This issue was discovered by Frediano Ziglio (Red Hat)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-September/008042.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice-gtk and / or spice-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spice-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spice-gtk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spice-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spice-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"spice-glib-0.26-8.el6_10.1")) flag++;
if (rpm_check(release:"EL6", reference:"spice-glib-devel-0.26-8.el6_10.1")) flag++;
if (rpm_check(release:"EL6", reference:"spice-gtk-0.26-8.el6_10.1")) flag++;
if (rpm_check(release:"EL6", reference:"spice-gtk-devel-0.26-8.el6_10.1")) flag++;
if (rpm_check(release:"EL6", reference:"spice-gtk-python-0.26-8.el6_10.1")) flag++;
if (rpm_check(release:"EL6", reference:"spice-gtk-tools-0.26-8.el6_10.1")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"spice-server-0.12.4-16.el6_10.1")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"spice-server-devel-0.12.4-16.el6_10.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-glib / spice-glib-devel / spice-gtk / spice-gtk-devel / etc");
}
