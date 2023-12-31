#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:567 and 
# CentOS Errata and Security Advisory 2005:567 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21946);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0175", "CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");
  script_xref(name:"RHSA", value:"2005:567");

  script_name(english:"CentOS 4 : krb5 (CESA-2005:567)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Kerberos is a networked authentication system that uses a trusted
third party (a KDC) to authenticate clients and servers to each other.

A double-free flaw was found in the krb5_recvauth() routine which may
be triggered by a remote unauthenticated attacker. Red Hat Enterprise
Linux 4 contains checks within glibc that detect double-free flaws.
Therefore, on Red Hat Enterprise Linux 4 successful exploitation of
this issue can only lead to a denial of service (KDC crash). The
Common Vulnerabilities and Exposures project assigned the name
CVE-2005-1689 to this issue.

Daniel Wachdorf discovered a single byte heap overflow in the
krb5_unparse_name() function, part of krb5-libs. Sucessful
exploitation of this flaw would lead to a denial of service (crash).
To trigger this flaw an attacker would need to have control of a
kerberos realm that shares a cross-realm key with the target, making
exploitation of this flaw unlikely. (CVE-2005-1175).

Daniel Wachdorf also discovered that in error conditions that may
occur in response to correctly-formatted client requests, the Kerberos
5 KDC may attempt to free uninitialized memory. This could allow a
remote attacker to cause a denial of service (KDC crash)
(CVE-2005-1174).

Gael Delalleau discovered an information disclosure issue in the way
some telnet clients handle messages from a server. An attacker could
construct a malicious telnet server that collects information from the
environment of any victim who connects to it using the Kerberos-aware
telnet client (CVE-2005-0488).

The rcp protocol allows a server to instruct a client to write to
arbitrary files outside of the current directory. This could
potentially cause a security issue if a user uses the Kerberos-aware
rcp to copy files from a malicious server (CVE-2004-0175).

All users of krb5 should update to these erratum packages, which
contain backported patches to correct these issues. Red Hat would like
to thank the MIT Kerberos Development Team for their responsible
disclosure of these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011927.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2337201"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011928.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bf2ad67"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011929.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4396db81"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"krb5-devel-1.3.4-17")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-libs-1.3.4-17")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-server-1.3.4-17")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-workstation-1.3.4-17")) flag++;


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
