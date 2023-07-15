#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0345 and 
# CentOS Errata and Security Advisory 2007:0345 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25254);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1856");
  script_bugtraq_id(23520);
  script_xref(name:"RHSA", value:"2007:0345");

  script_name(english:"CentOS 3 / 4 / 5 : vixie-cron (CESA-2007:0345)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vixie-cron packages that fix a denial of service issue are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The vixie-cron package contains the Vixie version of cron. Cron is a
standard UNIX daemon that runs specified programs at scheduled times.

Raphael Marichez discovered a denial of service bug in the way
vixie-cron verifies crontab file integrity. A local user with the
ability to create a hardlink to /etc/crontab can prevent vixie-cron
from executing certain system cron jobs. (CVE-2007-1856)

All users of vixie-cron should upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013768.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87a685e4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013770.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4a4c680"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013771.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4504c97"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013772.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2550b51"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013786.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f74db359"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013787.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77668d2d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013806.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d6171ff"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013807.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4a40410"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vixie-cron package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vixie-cron");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"vixie-cron-4.1-19.EL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"vixie-cron-4.1-47.EL4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"vixie-cron-4.1-70.el5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vixie-cron");
}
