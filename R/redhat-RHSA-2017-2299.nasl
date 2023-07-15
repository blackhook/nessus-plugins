#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2299. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102155);
  script_version("3.12");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-0553");
  script_xref(name:"RHSA", value:"2017:2299");

  script_name(english:"RHEL 7 : NetworkManager and libnl3 (RHSA-2017:2299)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for NetworkManager, NetworkManager-libreswan, libnl3, and
network-manager-applet is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

NetworkManager is a system network service that manages network
devices and connections, attempting to keep active network
connectivity when available. Its capabilities include managing
Ethernet, wireless, mobile broadband (WWAN), and PPPoE devices, as
well as providing VPN integration with a variety of different VPN
services.

The libnl3 packages contain a convenience library that simplifies
using the Linux kernel's Netlink sockets interface for network
manipulation.

The following packages have been upgraded to a later upstream version:
NetworkManager (1.8.0), network-manager-applet (1.8.0). (BZ#1413312,
BZ# 1414103, BZ#1441621)

Security Fix(es) in the libnl3 component :

* An integer overflow leading to a heap-buffer overflow was found in
the libnl library. An attacker could use this flaw to cause an
application compiled with libnl to crash or possibly execute arbitrary
code in the context of the user running such an application.
(CVE-2017-0553)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-0553"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-libreswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-libreswan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-libreswan-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-ppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnl3-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnl3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnl3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnm-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnm-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnma-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:network-manager-applet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nm-connection-editor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/07");
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

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2299";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-adsl-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-adsl-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-bluetooth-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"NetworkManager-config-server-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"NetworkManager-debuginfo-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"NetworkManager-dispatcher-routing-rules-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"NetworkManager-glib-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"NetworkManager-glib-devel-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"NetworkManager-libnm-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"NetworkManager-libnm-devel-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-libreswan-1.2.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-libreswan-1.2.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-libreswan-debuginfo-1.2.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-libreswan-debuginfo-1.2.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-libreswan-gnome-1.2.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-libreswan-gnome-1.2.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-ppp-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-ppp-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-team-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-team-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-tui-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-tui-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-wifi-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-wifi-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"NetworkManager-wwan-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"NetworkManager-wwan-1.8.0-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libnl3-3.2.28-4.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libnl3-cli-3.2.28-4.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libnl3-debuginfo-3.2.28-4.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libnl3-devel-3.2.28-4.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libnl3-doc-3.2.28-4.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libnl3-doc-3.2.28-4.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libnm-gtk-1.8.0-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libnm-gtk-devel-1.8.0-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libnma-1.8.0-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libnma-devel-1.8.0-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"network-manager-applet-1.8.0-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"network-manager-applet-1.8.0-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"network-manager-applet-debuginfo-1.8.0-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nm-connection-editor-1.8.0-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nm-connection-editor-1.8.0-3.el7")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-adsl / NetworkManager-bluetooth / etc");
  }
}
