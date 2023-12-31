#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0562 and 
# CentOS Errata and Security Advisory 2007:0562 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25580);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798");
  script_bugtraq_id(24653, 24655, 24657);
  script_xref(name:"RHSA", value:"2007:0562");

  script_name(english:"CentOS 4 / 5 : krb5 (CESA-2007:0562)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix several security flaws are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other through use of symmetric
encryption and a trusted third party, the KDC. kadmind is the KADM5
administration server.

David Coffey discovered an uninitialized pointer free flaw in the RPC
library used by kadmind. On Red Hat Enterprise Linux 4 and 5, glibc
detects attempts to free invalid pointers. A remote unauthenticated
attacker who can access kadmind could trigger this flaw and cause
kadmind to crash. (CVE-2007-2442)

David Coffey also discovered an overflow flaw in the RPC library used
by kadmind. On Red Hat Enterprise Linux, exploitation of this flaw is
limited to a denial of service. A remote unauthenticated attacker who
can access kadmind could trigger this flaw and cause kadmind to crash.
(CVE-2007-2443)

A stack-based buffer overflow flaw was found in kadmind. An
authenticated attacker who can access kadmind could trigger this flaw
and potentially execute arbitrary code on the Kerberos server.
(CVE-2007-2798)

Users of krb5-server are advised to update to these erratum packages
which contain backported fixes to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013982.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9b3d926"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013983.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?987c0fee"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013988.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70b8e129"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013989.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be8beaab"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/014004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02a17f7c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
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
if (rpm_check(release:"CentOS-4", reference:"krb5-devel-1.3.4-49")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-libs-1.3.4-49")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-server-1.3.4-49")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-workstation-1.3.4-49")) flag++;

if (rpm_check(release:"CentOS-5", reference:"krb5-devel-1.5-26")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-libs-1.5-26")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-server-1.5-26")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-workstation-1.5-26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
}
