#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0394 and 
# CentOS Errata and Security Advisory 2011:0394 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53504);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-0720");
  script_xref(name:"RHSA", value:"2011:0394");

  script_name(english:"CentOS 5 : conga (CESA-2011:0394)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated conga packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The conga packages provide a web-based administration tool for remote
cluster and storage management.

A privilege escalation flaw was found in luci, the Conga web-based
administration application. A remote attacker could possibly use this
flaw to obtain administrative access, allowing them to read, create,
or modify the content of the luci application. (CVE-2011-0720)

Users of Conga are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages, luci must be restarted ('service luci restart') for
the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09f1b03d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017421.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?149881a1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected conga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ricci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"luci-0.12.2-24.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ricci-0.12.2-24.el5.centos.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "luci / ricci");
}
