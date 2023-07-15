#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3665 and 
# Oracle Linux Security Advisory ELSA-2018-3665 respectively.
#

include('compat.inc');

if (description)
{
  script_id(119248);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id("CVE-2018-15688");
  script_xref(name:"RHSA", value:"2018:3665");

  script_name(english:"Oracle Linux 7 : NetworkManager (ELSA-2018-3665)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2018:3665 :

An update for NetworkManager is now available for Red Hat Enterprise
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
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2018-November/008287.html");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/28");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-ppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-adsl-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-config-server-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-dispatcher-routing-rules-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-glib-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-glib-devel-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libnm-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libnm-devel-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-ovs-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-ppp-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-team-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-tui-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-wifi-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-wwan-1.12.0-8.el7_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-adsl / NetworkManager-bluetooth / etc");
}
