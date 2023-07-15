#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0486 and 
# CentOS Errata and Security Advisory 2006:0486 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21901);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0052");
  script_xref(name:"RHSA", value:"2006:0486");

  script_name(english:"CentOS 3 / 4 : mailman (CESA-2006:0486)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mailman package that fixes a denial of service flaw is now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mailman is software to help manage email discussion lists.

A flaw was found in the way Mailman handles MIME multipart messages.
An attacker could send a carefully crafted MIME multipart email
message to a mailing list run by Mailman which would cause that
particular mailing list to stop working. (CVE-2006-0052)

Users of Mailman should upgrade to this updated package, which
contains backported patches to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-June/012949.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?118af39c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-June/012950.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86cb7050"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-June/012953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?427d4d16"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-June/012954.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56d55620"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-June/012955.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78010793"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-June/012957.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b79b2cf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mailman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/09");
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
if (rpm_check(release:"CentOS-3", reference:"mailman-2.1.5.1-25.rhel3.5")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mailman-2.1.5.1-34.rhel4.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman");
}
