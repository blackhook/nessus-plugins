#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2315 and 
# CentOS Errata and Security Advisory 2015:2315 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87149);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-0272", "CVE-2015-2924");
  script_xref(name:"RHSA", value:"2015:2315");

  script_name(english:"CentOS 7 : ModemManager / NetworkManager / NetworkManager-libreswan / network-manager-applet (CESA-2015:2315)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated NetworkManager packages that fix two security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

NetworkManager is a system network service that manages network
devices and connections.

It was discovered that NetworkManager would set device MTUs based on
MTU values received in IPv6 RAs (Router Advertisements), without
sanity checking the MTU value first. A remote attacker could exploit
this flaw to create a denial of service attack, by sending a specially
crafted IPv6 RA packet to disturb IPv6 communication. (CVE-2015-0272)

A flaw was found in the way NetworkManager handled router
advertisements. An unprivileged user on a local network could use IPv6
Neighbor Discovery ICMP to broadcast a non-route with a low hop limit,
causing machines to lower the hop limit on existing IPv6 routes. If
this limit is small enough, IPv6 packets would be dropped before
reaching the final destination. (CVE-2015-2924)

The network-manager-applet and NetworkManager-libreswan packages have
been upgraded to upstream versions 1.0.6, and provide a number of bug
fixes and enhancements over the previous versions. (BZ#1177582,
BZ#1243057)

Bugs :

* It was not previously possible to set the Wi-Fi band to the 'a' or
'bg' values to lock to a specific frequency band. NetworkManager has
been fixed, and it now sets the wpa_supplicant's 'freq_list' option
correctly, which enables proper Wi-Fi band locking. (BZ#1254461)

* NetworkManager immediately failed activation of devices that did not
have a carrier early in the boot process. The legacy network.service
then reported activation failure. Now, NetworkManager has a grace
period during which it waits for the carrier to appear. Devices that
have a carrier down for a short time on system startup no longer cause
the legacy network.service to fail. (BZ#1079353)

* NetworkManager brought down a team device if the teamd service
managing it exited unexpectedly, and the team device was deactivated.
Now, NetworkManager respawns the teamd instances that disappear and is
able to recover from a teamd failure avoiding disruption of the team
device operation. (BZ#1145988)

* NetworkManager did not send the FQDN DHCP option even if host name
was set to FQDN. Consequently, Dynamic DNS (DDNS) setups failed to
update the DNS records for clients running NetworkManager. Now,
NetworkManager sends the FQDN option with DHCP requests, and the DHCP
server is able to create DNS records for such clients. (BZ#1212597)

* The command-line client was not validating the vlan.flags property
correctly, and a spurious warning message was displayed when the nmcli
tool worked with VLAN connections. The validation routine has been
fixed, and the warning message no longer appears. (BZ#1244048)

* NetworkManager did not propagate a media access control (MAC)
address change from a bonding interface to a VLAN interface on top of
it. Consequently, a VLAN interface on top of a bond used an incorrect
MAC address. Now, NetworkManager synchronizes the addresses correctly.
(BZ#1264322)

Enhancements :

* IPv6 Privacy extensions are now enabled by default. NetworkManager
checks the per-network configuration files, NetworkManager.conf, and
then falls back to '/proc/sys/net/ipv6/conf/default/use_tempaddr' to
determine and set IPv6 privacy settings at device activation.
(BZ#1187525)

* The NetworkManager command-line tool, nmcli, now allows setting the
wake-on-lan property to 0 ('none', 'disable', 'disabled').
(BZ#1260584)

* NetworkManager now provides information about metered connections.
(BZ#1200452)

* NetworkManager daemon and the connection editor now support setting
the Maximum Transmission Unit (MTU) of a bond. It is now possible to
change MTU of a bond interface in a GUI. (BZ#1177582, BZ#1177860)

* NetworkManager daemon and the connection editor now support setting
the MTU of a team, allowing to change MTU of a teaming interface.
(BZ#1255927)

NetworkManager users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002487.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de82efed"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002500.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a75fb47f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002501.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2307d9db"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002502.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50f64ade"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0272");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ModemManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ModemManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ModemManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ModemManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ModemManager-vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-config-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libreswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libreswan-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnm-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnm-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nm-connection-editor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ModemManager-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ModemManager-devel-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ModemManager-glib-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ModemManager-glib-devel-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ModemManager-vala-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-adsl-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-config-routing-rules-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-config-server-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-devel-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-glib-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-glib-devel-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libnm-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libnm-devel-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libreswan-1.0.6-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libreswan-gnome-1.0.6-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-team-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-tui-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-wifi-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-wwan-1.0.6-27.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnm-gtk-1.0.6-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnm-gtk-devel-1.0.6-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"network-manager-applet-1.0.6-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nm-connection-editor-1.0.6-2.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ModemManager / ModemManager-devel / ModemManager-glib / etc");
}
