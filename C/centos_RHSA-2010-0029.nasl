#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0029 and 
# CentOS Errata and Security Advisory 2010:0029 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43866);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-4212");
  script_bugtraq_id(37749);
  script_xref(name:"RHSA", value:"2010:0029");

  script_name(english:"CentOS 3 / 4 / 5 : krb5 (CESA-2010:0029)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5, and Red Hat
Enterprise Linux 4.7, 5.2, and 5.3 Extended Update Support.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third party, the Key Distribution Center (KDC).

Multiple integer underflow flaws, leading to heap-based corruption,
were found in the way the MIT Kerberos Key Distribution Center (KDC)
decrypted ciphertexts encrypted with the Advanced Encryption Standard
(AES) and ARCFOUR (RC4) encryption algorithms. If a remote KDC client
were able to provide a specially crafted AES- or RC4-encrypted
ciphertext or texts, it could potentially lead to either a denial of
service of the central KDC (KDC crash or abort upon processing the
crafted ciphertext), or arbitrary code execution with the privileges
of the KDC (i.e., root privileges). (CVE-2009-4212)

All krb5 users should upgrade to these updated packages, which contain
a backported patch to correct these issues. All running services using
the MIT Kerberos libraries must be restarted for the update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016441.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3928f71"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016442.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7b6d35c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016453.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63052a55"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016454.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b727736e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016455.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c029756a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016456.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?555907ea"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/13");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"krb5-devel-1.2.7-71")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"krb5-devel-1.2.7-71")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"krb5-libs-1.2.7-71")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"krb5-libs-1.2.7-71")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"krb5-server-1.2.7-71")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"krb5-server-1.2.7-71")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"krb5-workstation-1.2.7-71")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"krb5-workstation-1.2.7-71")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-devel-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-devel-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-libs-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-libs-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-server-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-server-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-workstation-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-workstation-1.3.4-62.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"krb5-devel-1.6.1-36.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-libs-1.6.1-36.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-server-1.6.1-36.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-workstation-1.6.1-36.el5_4.1")) flag++;


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
