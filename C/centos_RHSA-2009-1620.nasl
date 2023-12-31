#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1620 and 
# CentOS Errata and Security Advisory 2009:1620 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43809);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-4022");
  script_bugtraq_id(37118);
  script_xref(name:"RHSA", value:"2009:1620");

  script_name(english:"CentOS 5 : bind (CESA-2009:1620)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

Michael Sinatra discovered that BIND was incorrectly caching responses
without performing proper DNSSEC validation, when those responses were
received during the resolution of a recursive client query that
requested DNSSEC records but indicated that checking should be
disabled. A remote attacker could use this flaw to bypass the DNSSEC
validation check and perform a cache poisoning attack if the target
BIND server was receiving such client queries. (CVE-2009-4022)

All BIND users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
update, the BIND daemon (named) will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-December/016364.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61c39e9b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-December/016365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f893ffd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
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
if (rpm_check(release:"CentOS-5", reference:"bind-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-chroot-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-devel-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libbind-devel-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libs-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-sdb-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-utils-9.3.6-4.P1.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"caching-nameserver-9.3.6-4.P1.el5_4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libbind-devel / bind-libs / etc");
}
