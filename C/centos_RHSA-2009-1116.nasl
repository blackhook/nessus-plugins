#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1116 and 
# CentOS Errata and Security Advisory 2009:1116 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43759);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0688");
  script_xref(name:"RHSA", value:"2009:1116");

  script_name(english:"CentOS 5 : cyrus-imapd (CESA-2009:1116)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cyrus-imapd packages that fix a security issue are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The cyrus-imapd packages contain a high-performance mail server with
IMAP, POP3, NNTP, and SIEVE support.

It was discovered that the Cyrus SASL library (cyrus-sasl) does not
always reliably terminate output from the sasl_encode64() function
used by programs using this library. The Cyrus IMAP server
(cyrus-imapd) relied on this function's output being properly
terminated. Under certain conditions, improperly terminated output
from sasl_encode64() could, potentially, cause cyrus-imapd to crash,
disclose portions of its memory, or lead to SASL authentication
failures. (CVE-2009-0688)

Users of cyrus-imapd are advised to upgrade to these updated packages,
which resolve this issue. After installing the update, cyrus-imapd
will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015977.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58f97b5b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015978.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42ba9f6b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/19");
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
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-2.3.7-2.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-devel-2.3.7-2.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-perl-2.3.7-2.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-utils-2.3.7-2.el5_3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd / cyrus-imapd-devel / cyrus-imapd-perl / etc");
}
