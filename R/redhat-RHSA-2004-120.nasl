#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:120. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12480);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0079", "CVE-2004-0081", "CVE-2004-0112");
  script_bugtraq_id(9899);
  script_xref(name:"RHSA", value:"2004:120");

  script_name(english:"RHEL 3 : openssl (RHSA-2004:120)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that fix several remote denial of service
vulnerabilities are available for Red Hat Enterprise Linux 3.

The OpenSSL toolkit implements Secure Sockets Layer (SSL v2/v3),
Transport Layer Security (TLS v1) protocols, and serves as a
full-strength general purpose cryptography library.

Testing performed by the OpenSSL group using the Codenomicon TLS Test
Tool uncovered a NULL pointer assignment in the
do_change_cipher_spec() function in OpenSSL 0.9.6c-0.9.6k and
0.9.7a-0.9.7c. A remote attacker could perform a carefully crafted
SSL/TLS handshake against a server that uses the OpenSSL library in
such a way as to cause OpenSSL to crash. Depending on the application
this could lead to a denial of service. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0079
to this issue.

Stephen Henson discovered a flaw in SSL/TLS handshaking code when
using Kerberos ciphersuites in OpenSSL 0.9.7a-0.9.7c. A remote
attacker could perform a carefully crafted SSL/TLS handshake against a
server configured to use Kerberos ciphersuites in such a way as to
cause OpenSSL to crash. Most applications have no ability to use
Kerberos ciphersuites and will therefore be unaffected by this issue.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0112 to this issue.

Testing performed by the OpenSSL group using the Codenomicon TLS Test
Tool uncovered a bug in older versions of OpenSSL 0.9.6 prior to
0.9.6d that may lead to a denial of service attack (infinite loop).
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0081 to this issue. This issue affects only
the OpenSSL compatibility packages shipped with Red Hat Enterprise
Linux 3.

These updated packages contain patches provided by the OpenSSL group
that protect against these issues.

Additionally, the version of libica included in the OpenSSL packages
has been updated to 1.3.5. This only affects IBM s390 and IBM eServer
zSeries customers and is required for the latest openCryptoki
packages.

NOTE: Because server applications are affected by this issue, users
are advised to either restart all services that use OpenSSL
functionality or restart their systems after installing these updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.codenomicon.com/testtools/tls/"
  );
  # http://www.niscc.gov.uk/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cpni.gov.uk/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2004:120"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:120";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", reference:"openssl-0.9.7a-33.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openssl-devel-0.9.7a-33.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openssl-perl-0.9.7a-33.4")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openssl096b-0.9.6b-16")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"s390", reference:"openssl096b-0.9.6b-16")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"openssl096b-0.9.6b-16")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl096b");
  }
}
