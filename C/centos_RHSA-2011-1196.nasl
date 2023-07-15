#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1196 and 
# CentOS Errata and Security Advisory 2011:1196 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55996);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2899");
  script_xref(name:"RHSA", value:"2011:1196");

  script_name(english:"CentOS 4 / 5 : system-config-printer (CESA-2011:1196)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated system-config-printer packages that fix one security issue are
now available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

system-config-printer is a print queue configuration tool with a
graphical user interface.

It was found that system-config-printer did not properly sanitize
NetBIOS and workgroup names when searching for network printers. A
remote attacker could use this flaw to execute arbitrary code with the
privileges of the user running system-config-printer. (CVE-2011-2899)

All users of system-config-printer are advised to upgrade to these
updated packages, which contain a backported patch to resolve this
issue. Running instances of system-config-printer must be restarted
for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017704.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99c33985"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017705.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f3b012a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20de7354"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b54dd29"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000212.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a83b2571"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000213.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4aca691d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected system-config-printer packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:system-config-printer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:system-config-printer-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:system-config-printer-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"system-config-printer-0.6.116.10-1.6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"system-config-printer-0.6.116.10-1.6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"system-config-printer-gui-0.6.116.10-1.6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"system-config-printer-gui-0.6.116.10-1.6.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"system-config-printer-0.7.32.10-1.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"system-config-printer-libs-0.7.32.10-1.el5_7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "system-config-printer / system-config-printer-gui / etc");
}
