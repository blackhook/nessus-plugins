#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1459 and 
# CentOS Errata and Security Advisory 2011:1459 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56880);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-4313");
  script_bugtraq_id(50690);
  script_xref(name:"RHSA", value:"2011:1459");

  script_name(english:"CentOS 5 : bind97 (CESA-2011:1459)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind97 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was discovered in the way BIND handled certain DNS queries,
which caused it to cache an invalid record. A remote attacker could
use this flaw to send repeated queries for this invalid record,
causing the resolvers to exit unexpectedly due to a failed assertion.
(CVE-2011-4313)

Users of bind97 are advised to upgrade to these updated packages,
which resolve this issue. After installing the update, the BIND daemon
(named) will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-November/018209.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a19793f7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-November/018210.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14a961ab"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind97 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/22");
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
if (rpm_check(release:"CentOS-5", reference:"bind97-9.7.0-6.P2.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-chroot-9.7.0-6.P2.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-devel-9.7.0-6.P2.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-libs-9.7.0-6.P2.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-utils-9.7.0-6.P2.el5_7.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind97 / bind97-chroot / bind97-devel / bind97-libs / bind97-utils");
}