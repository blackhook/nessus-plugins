#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1815 and 
# CentOS Errata and Security Advisory 2011:1815 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57291);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-4599");
  script_bugtraq_id(51006);
  script_xref(name:"RHSA", value:"2011:1815");

  script_name(english:"CentOS 5 / 6 : icu (CESA-2011:1815)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated icu packages that fix one security issue are now available for
Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The International Components for Unicode (ICU) library provides robust
and full-featured Unicode services.

A stack-based buffer overflow flaw was found in the way ICU performed
variant canonicalization for some locale identifiers. If a specially
crafted locale representation was opened in an application linked
against ICU, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-4599)

All users of ICU should upgrade to these updated packages, which
contain a backported patch to resolve this issue. All applications
linked against ICU must be restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-December/018323.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f6df519"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-December/018324.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0ec6869"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-December/018340.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd404633"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected icu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:icu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libicu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libicu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libicu-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"icu-3.6-5.16.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libicu-3.6-5.16.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libicu-devel-3.6-5.16.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libicu-doc-3.6-5.16.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"icu-4.2.1-9.1.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libicu-4.2.1-9.1.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libicu-devel-4.2.1-9.1.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libicu-doc-4.2.1-9.1.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icu / libicu / libicu-devel / libicu-doc");
}
