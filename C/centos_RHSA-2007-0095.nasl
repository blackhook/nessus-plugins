#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0095 and 
# CentOS Errata and Security Advisory 2007:0095 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24919);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0956", "CVE-2007-0957", "CVE-2007-1216");
  script_bugtraq_id(23281, 23282, 23285);
  script_xref(name:"RHSA", value:"2007:0095");

  script_name(english:"CentOS 3 / 4 : krb5 (CESA-2007:0095)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix a number of issues are now available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other through use of symmetric
encryption and a trusted third party, the KDC.

A flaw was found in the username handling of the MIT krb5 telnet
daemon (telnetd). A remote attacker who can access the telnet port of
a target machine could log in as root without requiring a password.
(CVE-2007-0956)

Note that the krb5 telnet daemon is not enabled by default in any
version of Red Hat Enterprise Linux. In addition, the default firewall
rules block remote access to the telnet port. This flaw does not
affect the telnet daemon distributed in the telnet-server package.

For users who have enabled the krb5 telnet daemon and have it
accessible remotely, this update should be applied immediately.

Whilst we are not aware at this time that the flaw is being actively
exploited, we have confirmed that the flaw is very easily exploitable.

This update also fixes two additional security issues :

Buffer overflows were found which affect the Kerberos KDC and the
kadmin server daemon. A remote attacker who can access the KDC could
exploit this bug to run arbitrary code with the privileges of the KDC
or kadmin server processes. (CVE-2007-0957)

A double-free flaw was found in the GSSAPI library used by the kadmin
server daemon. Red Hat Enterprise Linux 4 and 5 contain checks within
glibc that detect double-free flaws. Therefore, on Red Hat Enterprise
Linux 4 and 5 successful exploitation of this issue can only lead to a
denial of service. Applications which use this library in earlier
releases of Red Hat Enterprise Linux may also be affected.
(CVE-2007-1216)

All users are advised to update to these erratum packages which
contain a backported fix to correct these issues.

Red Hat would like to thank MIT and iDefense for reporting these
vulnerabilities."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013638.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aa5d1e6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013639.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4656c7f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013642.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84f46e52"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013645.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c04ec56e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013656.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a718abc3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013657.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1929be5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/05");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"krb5-devel-1.2.7-61")) flag++;
if (rpm_check(release:"CentOS-3", reference:"krb5-libs-1.2.7-61")) flag++;
if (rpm_check(release:"CentOS-3", reference:"krb5-server-1.2.7-61")) flag++;
if (rpm_check(release:"CentOS-3", reference:"krb5-workstation-1.2.7-61")) flag++;

if (rpm_check(release:"CentOS-4", reference:"krb5-devel-1.3.4-46")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-libs-1.3.4-46")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-server-1.3.4-46")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-workstation-1.3.4-46")) flag++;


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
