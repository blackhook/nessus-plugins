#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2732. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117626);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/28");

  script_cve_id("CVE-2018-10873");
  script_xref(name:"RHSA", value:"2018:2732");

  script_name(english:"RHEL 6 : spice-gtk and spice-server (RHSA-2018:2732)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for spice-gtk and spice-server is now available for Red Hat
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
    value:"https://access.redhat.com/errata/RHSA-2018:2732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10873"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:2732";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-glib-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-glib-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-glib-devel-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-glib-devel-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-debuginfo-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-debuginfo-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-devel-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-devel-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-python-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-python-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"spice-gtk-tools-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-gtk-tools-0.26-8.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-server-0.12.4-16.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-server-debuginfo-0.12.4-16.el6_10.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"spice-server-devel-0.12.4-16.el6_10.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-glib / spice-glib-devel / spice-gtk / spice-gtk-debuginfo / etc");
  }
}
