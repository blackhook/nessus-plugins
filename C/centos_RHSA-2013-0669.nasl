#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0669 and 
# CentOS Errata and Security Advisory 2013:0669 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65661);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0254");
  script_bugtraq_id(57772);
  script_xref(name:"RHSA", value:"2013:0669");

  script_name(english:"CentOS 6 : qt (CESA-2013:0669)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qt packages that fix one security issue are now available for
Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System.

It was discovered that the QSharedMemory class implementation of the
Qt toolkit created shared memory segments with insecure permissions. A
local attacker could use this flaw to read or alter the contents of a
particular shared memory segment, possibly leading to their ability to
obtain sensitive information or influence the behavior of a process
that is using the shared memory segment. (CVE-2013-0254)

Red Hat would like to thank the Qt project for reporting this issue.
Upstream acknowledges Tim Brown and Mark Lowe of Portcullis Computer
Security Ltd. as the original reporters.

Users of Qt should upgrade to these updated packages, which contain a
backported patch to correct this issue. All running applications
linked against Qt libraries must be restarted for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019662.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04721979"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0254");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:phonon-backend-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"phonon-backend-gstreamer-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-demos-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-devel-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-doc-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-examples-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-mysql-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-odbc-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-postgresql-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-sqlite-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qt-x11-4.6.2-26.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phonon-backend-gstreamer / qt / qt-demos / qt-devel / qt-doc / etc");
}
