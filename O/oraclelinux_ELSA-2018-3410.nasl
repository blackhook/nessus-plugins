#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3410 and 
# Oracle Linux Security Advisory ELSA-2018-3410 respectively.
#

include("compat.inc");

if (description)
{
  script_id(118812);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/14");

  script_cve_id("CVE-2018-14665");
  script_xref(name:"RHSA", value:"2018:3410");

  script_name(english:"Oracle Linux 7 : xorg-x11-server (ELSA-2018-3410)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2018:3410 :

An update for xorg-x11-server is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

Security Fix(es) :

* xorg-x11-server: Incorrect permission check in Xorg X server allows
for privilege escalation (CVE-2018-14665)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Narendra Shinde for reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-November/008225.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Xorg X11 Server SUID modulepath Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.20.1-5.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.20.1-5.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.20.1-5.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.20.1-5.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.20.1-5.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xwayland-1.20.1-5.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-common-1.20.1-5.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.20.1-5.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-source-1.20.1-5.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
}
