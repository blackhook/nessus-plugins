#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1413. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117315);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-6304", "CVE-2016-7056", "CVE-2016-8610", "CVE-2016-8740", "CVE-2016-8743");
  script_xref(name:"RHSA", value:"2017:1413");

  script_name(english:"RHEL 7 : JBoss Core Services (RHSA-2017:1413)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat JBoss Core Services on RHEL 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Core Services is a set of supplementary software for Red
Hat JBoss middleware products. This software, such as Apache HTTP
Server, is common to multiple JBoss middleware products, and is
packaged under Red Hat JBoss Core Services to allow for faster
distribution of updates, and for a more consistent update experience.

This release of Red Hat JBoss Core Services Apache HTTP Server 2.4.23
Service Pack 1 serves as a replacement for Red Hat JBoss Core Services
Apache HTTP Server 2.4.23, and includes bug fixes, which are
documented in the Release Notes document linked to in the References.

Security Fix(es) :

* A memory leak flaw was found in the way OpenSSL handled TLS status
request extension data during session renegotiation. A remote attacker
could cause a TLS server using OpenSSL to consume an excessive amount
of memory and, possibly, exit unexpectedly after exhausting all
available memory, if it enabled OCSP stapling support. (CVE-2016-6304)

* It was discovered that the mod_session_crypto module of httpd did
not use any mechanisms to verify integrity of the encrypted session
data stored in the user's browser. A remote attacker could use this
flaw to decrypt and modify session data using a padding oracle attack.
(CVE-2016-0736)

* It was discovered that the mod_auth_digest module of httpd did not
properly check for memory allocation failures. A remote attacker could
use this flaw to cause httpd child processes to repeatedly crash if
the server used HTTP digest authentication. (CVE-2016-2161)

* A timing attack flaw was found in OpenSSL that could allow a
malicious user with local access to recover ECDSA P-256 private keys.
(CVE-2016-7056)

* A denial of service flaw was found in the way the TLS/SSL protocol
defined processing of ALERT packets during a connection handshake. A
remote attacker could use this flaw to make a TLS/SSL server consume
an excessive amount of CPU and fail to accept connections from other
clients. (CVE-2016-8610)

* It was discovered that the HTTP parser in httpd incorrectly allowed
certain characters not permitted by the HTTP protocol specification to
appear unencoded in HTTP request headers. If httpd was used in
conjunction with a proxy or backend server that interpreted those
characters differently, a remote attacker could possibly use this flaw
to inject data into HTTP responses, resulting in proxy cache
poisoning. (CVE-2016-8743)

* A vulnerability was found in httpd's handling of the
LimitRequestFields directive in mod_http2, affecting servers with
HTTP/2 enabled. An attacker could send crafted requests with headers
larger than the server's available memory, causing httpd to crash.
(CVE-2016-8740)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2016-6304 and Shi Lei (Gear Team of Qihoo 360 Inc.) for reporting
CVE-2016-8610. Upstream acknowledges Shi Lei (Gear Team of Qihoo 360
Inc.) as the original reporter of CVE-2016-6304."
  );
  # https://access.redhat.com/documentation/en/red-hat-jboss-core-services/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75d9eb14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-0736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8743"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_security-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1413";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-debuginfo-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-devel-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-libs-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbcs-httpd24-httpd-manual-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-selinux-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-tools-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_ldap-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_proxy_html-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_security-2.9.1-19.GA.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_security-debuginfo-2.9.1-19.GA.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_session-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_ssl-2.4.23-120.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-devel-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-libs-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-perl-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-static-1.0.2h-13.jbcs.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbcs-httpd24-httpd / jbcs-httpd24-httpd-debuginfo / etc");
  }
}
