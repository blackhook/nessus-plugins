#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1426 and 
# Oracle Linux Security Advisory ELSA-2013-1426 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70450);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4396");
  script_bugtraq_id(62892);
  script_xref(name:"RHSA", value:"2013:1426");

  script_name(english:"Oracle Linux 5 / 6 : xorg-x11-server (ELSA-2013-1426)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1426 :

Updated xorg-x11-server packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

A use-after-free flaw was found in the way the X.Org server handled
ImageText requests. A malicious, authorized client could use this flaw
to crash the X.Org server or, potentially, execute arbitrary code with
root privileges. (CVE-2013-4396)

Red Hat would like to thank the X.Org security team for reporting this
issue. Upstream acknowledges Pedro Ribeiro as the original reporter.

All xorg-x11-server users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-October/003727.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-October/003728.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xvnc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"xorg-x11-server-Xdmx-1.1.1-48.101.0.1.el5_10.1")) flag++;
if (rpm_check(release:"EL5", reference:"xorg-x11-server-Xephyr-1.1.1-48.101.0.1.el5_10.1")) flag++;
if (rpm_check(release:"EL5", reference:"xorg-x11-server-Xnest-1.1.1-48.101.0.1.el5_10.1")) flag++;
if (rpm_check(release:"EL5", reference:"xorg-x11-server-Xorg-1.1.1-48.101.0.1.el5_10.1")) flag++;
if (rpm_check(release:"EL5", reference:"xorg-x11-server-Xvfb-1.1.1-48.101.0.1.el5_10.1")) flag++;
if (rpm_check(release:"EL5", reference:"xorg-x11-server-Xvnc-source-1.1.1-48.101.0.1.el5_10.1")) flag++;
if (rpm_check(release:"EL5", reference:"xorg-x11-server-sdk-1.1.1-48.101.0.1.el5_10.1")) flag++;

if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xdmx-1.13.0-11.1.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xephyr-1.13.0-11.1.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xnest-1.13.0-11.1.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xorg-1.13.0-11.1.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xvfb-1.13.0-11.1.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-common-1.13.0-11.1.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-devel-1.13.0-11.1.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-source-1.13.0-11.1.el6_4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
}
