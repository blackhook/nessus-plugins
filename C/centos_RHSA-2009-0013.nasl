#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0013 and 
# CentOS Errata and Security Advisory 2009:0013 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43726);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-5081");
  script_bugtraq_id(32825);
  script_xref(name:"RHSA", value:"2009:0013");

  script_name(english:"CentOS 5 : avahi (CESA-2009:0013)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated avahi packages that fix a security issue are now available for
Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Avahi is an implementation of the DNS Service Discovery and Multicast
DNS specifications for Zeroconf Networking. It facilitates service
discovery on a local network. Avahi and Avahi-aware applications allow
you to plug your computer into a network and, with no configuration,
view other people to chat with, see printers to print to, and find
shared files on other computers.

Hugo Dias discovered a denial of service flaw in avahi-daemon. A
remote attacker on the same local area network (LAN) could send a
specially crafted mDNS (Multicast DNS) packet that would cause
avahi-daemon to exit unexpectedly due to a failed assertion check.
(CVE-2008-5081)

All users are advised to upgrade to these updated packages, which
contain a backported patch which resolves this issue. After installing
the update, avahi-daemon will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015542.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0a68cff"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015543.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f42d73e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected avahi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-howl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if (rpm_check(release:"CentOS-5", reference:"avahi-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-howl-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-howl-devel-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-libdns_sd-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-libdns_sd-devel-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-devel-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-glib-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-glib-devel-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-qt3-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-qt3-devel-0.6.16-1.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-tools-0.6.16-1.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi / avahi-compat-howl / avahi-compat-howl-devel / etc");
}
