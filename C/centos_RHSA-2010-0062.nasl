#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0062 and 
# CentOS Errata and Security Advisory 2010:0062 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44099);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0097", "CVE-2010-0290", "CVE-2010-0382");
  script_bugtraq_id(37118, 37865);
  script_xref(name:"RHSA", value:"2010:0062");

  script_name(english:"CentOS 5 : bind (CESA-2010:0062)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was found in the BIND DNSSEC NSEC/NSEC3 validation code. If
BIND was running as a DNSSEC-validating resolver, it could incorrectly
cache NXDOMAIN responses, as if they were valid, for records proven by
NSEC or NSEC3 to exist. A remote attacker could use this flaw to cause
a BIND server to return the bogus, cached NXDOMAIN responses for valid
records and prevent users from retrieving those records (denial of
service). (CVE-2010-0097)

The original fix for CVE-2009-4022 was found to be incomplete. BIND
was incorrectly caching certain responses without performing proper
DNSSEC validation. CNAME and DNAME records could be cached, without
proper DNSSEC validation, when received from processing recursive
client queries that requested DNSSEC records but indicated that
checking should be disabled. A remote attacker could use this flaw to
bypass the DNSSEC validation check and perform a cache poisoning
attack if the target BIND server was receiving such client queries.
(CVE-2010-0290)

All BIND users are advised to upgrade to these updated packages, which
contain a backported patch to resolve these issues. After installing
the update, the BIND daemon (named) will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016477.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a4e3ef7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016478.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b608743b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/21");
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
if (rpm_check(release:"CentOS-5", reference:"bind-9.3.6-4.P1.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-chroot-9.3.6-4.P1.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-devel-9.3.6-4.P1.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libbind-devel-9.3.6-4.P1.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libs-9.3.6-4.P1.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-sdb-9.3.6-4.P1.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-utils-9.3.6-4.P1.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"caching-nameserver-9.3.6-4.P1.el5_4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libbind-devel / bind-libs / etc");
}
