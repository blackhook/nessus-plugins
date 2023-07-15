#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1648 and 
# CentOS Errata and Security Advisory 2009:1648 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43071);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-3563");
  script_xref(name:"RHSA", value:"2009:1648");

  script_name(english:"CentOS 4 / 5 : ntp (CESA-2009:1648)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ntp package that fixes a security issue is now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with a referenced time source.

Robin Park and Dmitri Vinokurov discovered a flaw in the way ntpd
handled certain malformed NTP packets. ntpd logged information about
all such packets and replied with an NTP packet that was treated as
malformed when received by another ntpd. A remote attacker could use
this flaw to create an NTP packet reply loop between two ntpd servers
via a malformed packet with a spoofed source IP address and port,
causing ntpd on those servers to use excessive amounts of CPU time and
fill disk space with log messages. (CVE-2009-3563)

All ntp users are advised to upgrade to this updated package, which
contains a backported patch to resolve this issue. After installing
the update, the ntpd daemon will restart automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-December/016360.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96d8db42"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-December/016361.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c315a515"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-December/016405.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6dc67174"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-December/016406.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a95f2d9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ntp-4.2.0.a.20040617-8.el4_8.2.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ntp-4.2.0.a.20040617-8.el4_8.2.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"ntp-4.2.2p1-9.el5.centos.2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
