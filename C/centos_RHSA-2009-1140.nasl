#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1140 and 
# CentOS Errata and Security Advisory 2009:1140 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43767);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1558", "CVE-2009-0642", "CVE-2009-1904");
  script_bugtraq_id(23257, 35278);
  script_xref(name:"RHSA", value:"2009:1140");

  script_name(english:"CentOS 5 : ruby (CESA-2009:1140)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A flaw was found in the way the Ruby POP module processed certain APOP
authentication requests. By sending certain responses when the Ruby
APOP module attempted to authenticate using APOP against a POP server,
a remote attacker could, potentially, acquire certain portions of a
user's authentication credentials. (CVE-2007-1558)

It was discovered that Ruby did not properly check the return value
when verifying X.509 certificates. This could, potentially, allow a
remote attacker to present an invalid X.509 certificate, and have Ruby
treat it as valid. (CVE-2009-0642)

A flaw was found in the way Ruby converted BigDecimal objects to Float
numbers. If an attacker were able to provide certain input for the
BigDecimal object converter, they could crash an application using
this class. (CVE-2009-1904)

All Ruby users should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d49c05e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b8781ca"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"ruby-1.8.5-5.el5_3.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-devel-1.8.5-5.el5_3.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-docs-1.8.5-5.el5_3.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-irb-1.8.5-5.el5_3.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-libs-1.8.5-5.el5_3.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-mode-1.8.5-5.el5_3.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-rdoc-1.8.5-5.el5_3.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-ri-1.8.5-5.el5_3.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-tcltk-1.8.5-5.el5_3.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-devel / ruby-docs / ruby-irb / ruby-libs / ruby-mode / etc");
}
