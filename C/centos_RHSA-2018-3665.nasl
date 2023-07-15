#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3665 and 
# CentOS Errata and Security Advisory 2018:3665 respectively.
#

include('compat.inc');

if (description)
{
  script_id(119664);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id("CVE-2018-15688");
  script_xref(name:"RHSA", value:"2018:3665");

  script_name(english:"CentOS 7 : NetworkManager (CESA-2018:3665)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for NetworkManager is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

NetworkManager is a system network service that manages network
devices and connections, attempting to keep active network
connectivity when available. Its capabilities include managing
Ethernet, wireless, mobile broadband (WWAN), and PPPoE devices, as
well as providing VPN integration with a variety of different VPN
services.

Security Fix(es) :

* systemd: Out-of-bounds heap write in systemd-networkd dhcpv6 option
handling (CVE-2018-15688)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Ubuntu Security Team for reporting this
issue. Upstream acknowledges Felix Wilhelm (Google) as the original
reporter.");
  # https://lists.centos.org/pipermail/centos-announce/2018-December/023116.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aefa21a1");
  script_set_attribute(attribute:"solution", value:
"Update the affected networkmanager packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15688");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-ppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-adsl-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-config-server-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-dispatcher-routing-rules-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-glib-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-glib-devel-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libnm-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libnm-devel-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-ovs-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-ppp-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-team-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-tui-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-wifi-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-wwan-1.12.0-8.el7_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-adsl / NetworkManager-bluetooth / etc");
}
