#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0197 and 
# CentOS Errata and Security Advisory 2006:0197 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21890);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2491");
  script_bugtraq_id(14620);
  script_xref(name:"RHSA", value:"2006:0197");

  script_name(english:"CentOS 3 / 4 : python (CESA-2006:0197)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Python packages are now available to correct a security issue.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Python is an interpreted, interactive, object-oriented programming
language.

An integer overflow flaw was found in Python's PCRE library that could
be triggered by a maliciously crafted regular expression. On systems
that accept arbitrary regular expressions from untrusted users, this
could be exploited to execute arbitrary code with the privileges of
the application using the library. The Common Vulnerabilities and
Exposures project assigned the name CVE-2005-2491 to this issue.

Users of Python should upgrade to these updated packages, which
contain a backported patch that is not vulnerable to this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012715.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b301f75"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012716.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85ad353f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012721.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c04a9ca3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012722.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e9acd73"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97007871"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012737.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2c6dc6c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"python-2.2.3-6.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"python-devel-2.2.3-6.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"python-docs-2.2.3-6.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"python-tools-2.2.3-6.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tkinter-2.2.3-6.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"python-2.3.4-14.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"python-devel-2.3.4-14.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"python-docs-2.3.4-14.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"python-tools-2.3.4-14.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tkinter-2.3.4-14.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-devel / python-docs / python-tools / tkinter");
}
