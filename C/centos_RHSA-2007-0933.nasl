#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0933 and 
# CentOS Errata and Security Advisory 2007:0933 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26929);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-5034");
  script_xref(name:"RHSA", value:"2007:0933");

  script_name(english:"CentOS 4 / 5 : elinks (CESA-2007:0933)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ELinks package that corrects a security vulnerability is
now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ELinks is a text mode Web browser used from the command line that
supports rendering modern web pages.

An information disclosure flaw was found in the way ELinks passes
https POST data to a proxy server. POST data sent via a proxy to an
https site is not properly encrypted by ELinks, possibly allowing the
disclosure of sensitive information. (CVE-2007-5034)

All users of Elinks are advised to upgrade to this updated package,
which contains a backported patch that resolves this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014274.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34729a29"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014279.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5901362"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014280.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be257557"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014281.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dc23d08"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014282.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bea87880"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elinks package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elinks");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/09");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"elinks-0.9.2-3.3.5.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"elinks-0.11.1-5.1.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elinks");
}
