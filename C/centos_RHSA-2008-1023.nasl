#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:1023 and 
# CentOS Errata and Security Advisory 2008:1023 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35260);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-2955", "CVE-2008-2957", "CVE-2008-3532");
  script_xref(name:"RHSA", value:"2008:1023");

  script_name(english:"CentOS 4 / 5 : pidgin (CESA-2008:1023)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Pidgin packages that fix several security issues and bugs are
now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pidgin is a multi-protocol Internet Messaging client.

A denial-of-service flaw was found in Pidgin's MSN protocol handler.
If a remote user was able to send, and the Pidgin user accepted, a
carefully-crafted file request, it could result in Pidgin crashing.
(CVE-2008-2955)

A denial-of-service flaw was found in Pidgin's Universal Plug and Play
(UPnP) request handling. A malicious UPnP server could send a request
to Pidgin, causing it to download an excessive amount of data,
consuming all available memory or disk space. (CVE-2008-2957)

A flaw was found in the way Pidgin handled SSL certificates. The NSS
SSL implementation in Pidgin did not properly verify the authenticity
of SSL certificates. This could have resulted in users unknowingly
connecting to a malicious SSL service. (CVE-2008-3532)

In addition, this update upgrades pidgin from version 2.3.1 to version
2.5.2, with many additional stability and functionality fixes from the
Pidgin Project.

Note: the Secure Internet Live Conferencing (SILC) chat network
protocol has recently changed, affecting all versions of pidgin
shipped with Red Hat Enterprise Linux.

Pidgin cannot currently connect to the latest version of the SILC
server (1.1.14): it fails to properly exchange keys during initial
login. This update does not correct this. Red Hat Bugzilla #474212
(linked to in the References section) has more information.

Note: after the errata packages are installed, Pidgin must be
restarted for the update to take effect.

All Pidgin users should upgrade to these updated packages, which
contains Pidgin version 2.5.2 and resolves these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58e739c3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015487.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90a1496b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015488.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63d0fccf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015512.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a93aacbd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015513.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac4f036c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", reference:"finch-2.5.2-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"finch-devel-2.5.2-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libpurple-2.5.2-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libpurple-devel-2.5.2-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libpurple-perl-2.5.2-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libpurple-tcl-2.5.2-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"pidgin-2.5.2-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"pidgin-devel-2.5.2-6.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"pidgin-perl-2.5.2-6.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"finch-2.5.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.5.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.5.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.5.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.5.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.5.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.5.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.5.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-docs-2.5.2-6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.5.2-6.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
