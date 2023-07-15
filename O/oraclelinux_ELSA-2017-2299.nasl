#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2299 and 
# Oracle Linux Security Advisory ELSA-2017-2299 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102341);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-0553");
  script_xref(name:"RHSA", value:"2017:2299");

  script_name(english:"Oracle Linux 7 : NetworkManager / libnl3 (ELSA-2017-2299)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2299 :

An update for NetworkManager, NetworkManager-libreswan, libnl3, and
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007113.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libnl3 and / or networkmanager packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libreswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libreswan-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-ppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnm-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnm-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnma-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nm-connection-editor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-adsl-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-config-server-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-dispatcher-routing-rules-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-glib-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-glib-devel-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libnm-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libnm-devel-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libreswan-1.2.4-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libreswan-gnome-1.2.4-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-ppp-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-team-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-tui-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-wifi-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-wwan-1.8.0-9.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnl3-3.2.28-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnl3-cli-3.2.28-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnl3-devel-3.2.28-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnl3-doc-3.2.28-4.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnm-gtk-1.8.0-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnm-gtk-devel-1.8.0-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnma-1.8.0-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnma-devel-1.8.0-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"network-manager-applet-1.8.0-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nm-connection-editor-1.8.0-3.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-adsl / NetworkManager-bluetooth / etc");
}
