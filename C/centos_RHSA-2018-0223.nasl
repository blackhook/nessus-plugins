#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0223 and 
# CentOS Errata and Security Advisory 2018:0223 respectively.
#

include("compat.inc");

if (description)
{
  script_id(106356);
  script_version("3.7");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2017-14604");
  script_xref(name:"RHSA", value:"2018:0223");

  script_name(english:"CentOS 7 : nautilus (CESA-2018:0223)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for nautilus is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Nautilus is the file manager and graphical shell for the GNOME
desktop.

Security Fix(es) :

* An untrusted .desktop file with executable permission set could
choose its displayed name and icon, and execute commands without
warning when opened by the user. An attacker could use this flaw to
trick a user into opening a .desktop file disguised as a document,
such as a PDF, and execute arbitrary commands. (CVE-2017-14604)

Note: This update will change the behavior of Nautilus. Nautilus will
now prompt the user for confirmation when executing an untrusted
.desktop file for the first time, and then add it to the trusted file
list. Desktop files stored in the system directory, as specified by
the XDG_DATA_DIRS environment variable, are always considered trusted
and executed without prompt."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-January/022734.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15f53feb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nautilus packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14604");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-3.22.3-4.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-devel-3.22.3-4.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-extensions-3.22.3-4.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nautilus / nautilus-devel / nautilus-extensions");
}
