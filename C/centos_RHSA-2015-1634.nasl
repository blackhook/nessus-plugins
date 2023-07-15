#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1634 and 
# CentOS Errata and Security Advisory 2015:1634 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85462);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-3416");
  script_xref(name:"RHSA", value:"2015:1634");

  script_name(english:"CentOS 6 : sqlite (CESA-2015:1634)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sqlite package that fixes one security issue is now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

SQLite is a C library that implements a SQL database engine. A large
subset of SQL92 is supported. A complete database is stored in a
single disk file. The API is designed for convenience and ease of use.
Applications that link against SQLite can enjoy the power and
flexibility of a SQL database without the administrative hassles of
supporting a separate database server.

It was found that SQLite's sqlite3VXPrintf() function did not properly
handle precision and width values during floating-point conversions. A
local attacker could submit a specially crafted SELECT statement that
would crash the SQLite process, or have other unspecified impacts.
(CVE-2015-3416)

All sqlite users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-August/021332.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94b45529"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sqlite packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3416");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"lemon-3.6.20-1.el6_7.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sqlite-3.6.20-1.el6_7.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sqlite-devel-3.6.20-1.el6_7.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sqlite-doc-3.6.20-1.el6_7.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sqlite-tcl-3.6.20-1.el6_7.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lemon / sqlite / sqlite-devel / sqlite-doc / sqlite-tcl");
}
