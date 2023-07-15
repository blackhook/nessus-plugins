#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0367. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122292);
  script_version("1.5");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-0739", "CVE-2018-1000168", "CVE-2018-11759", "CVE-2018-11763", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1302", "CVE-2018-1303", "CVE-2018-1312", "CVE-2018-1333");
  script_xref(name:"RHSA", value:"2019:0367");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Core Services Apache HTTP Server 2.4.29 (RHSA-2019:0367)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for JBoss Core Services on RHEL 6 and RHEL
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE links in the References section.

Red Hat JBoss Core Services is a set of supplementary software for Red
Hat JBoss middleware products. This software, such as Apache HTTP
Server, is common to multiple JBoss middleware products, and is
packaged under Red Hat JBoss Core Services to allow for faster
distribution of updates, and for a more consistent update experience.

This release of Red Hat JBoss Core Services Apache HTTP Server 2.4.29
Service Pack 1 serves as an update to Red Hat JBoss Core Services
Apache HTTP Server 2.4.29, and includes bug fixes for CVEs which are
linked to in the References section.

Security Fixes :

* httpd: DoS for HTTP/2 connections by continuous SETTINGS
(CVE-2018-11763)

* httpd: Weak Digest auth nonce generation in mod_auth_digest
(CVE-2018-1312)

* httpd: Out of bound access after failure in reading the HTTP request
(CVE-2018-1301)

* httpd: Use-after-free on HTTP/2 stream shutdown (CVE-2018-1302)

* httpd: bypass with a trailing newline in the file name
(CVE-2017-15715)

* httpd: Out of bound write in mod_authnz_ldap when using too small
Accept-Language values (CVE-2017-15710)

* httpd: Out of bounds read in mod_cache_socache can allow a remote
attacker to cause a denial of service (CVE-2018-1303)

* httpd: Improper handling of headers in mod_session can allow a
remote user to modify session data for CGI applications
(CVE-2018-1283)

* httpd: mod_http2: too much time allocated to workers, possibly
leading to DoS (CVE-2018-1333)

* mod_jk: connector path traversal due to mishandled HTTP requests in
httpd (CVE-2018-11759)

* nghttp2: NULL pointer dereference when too large ALTSVC frame is
received (CVE-2018-1000168)

* openssl: Handling of crafted recursive ASN.1 structures can cause a
stack overflow and resulting denial of service (CVE-2018-0739)

Details around each issue, including information about the CVE,
severity of the issue, and the CVSS score, can be found on the CVE
pages listed in the Reference section below."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-0739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-11759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-11763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1000168"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apache-commons-daemon-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apache-commons-daemon-jsvc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_cluster-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_jk-ap24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_jk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_jk-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-nghttp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-nghttp2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:0367";
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
  if (rpm_check(release:"RHEL6", reference:"jbcs-httpd24-1-6.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apache-commons-daemon-jsvc-1.1.0-3.redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apache-commons-daemon-jsvc-1.1.0-3.redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apache-commons-daemon-jsvc-debuginfo-1.1.0-3.redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apache-commons-daemon-jsvc-debuginfo-1.1.0-3.redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-1.6.3-31.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-1.6.3-31.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-debuginfo-1.6.3-31.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-debuginfo-1.6.3-31.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-devel-1.6.3-31.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-devel-1.6.3-31.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-debuginfo-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-debuginfo-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-devel-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-devel-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-ldap-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-ldap-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-mysql-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-mysql-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-nss-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-nss-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-odbc-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-odbc-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-openssl-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-openssl-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-pgsql-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-pgsql-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-sqlite-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-sqlite-1.6.1-24.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-debuginfo-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-debuginfo-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-devel-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-devel-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbcs-httpd24-httpd-manual-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-selinux-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-selinux-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-tools-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-tools-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_cluster-native-1.3.8-3.Final_redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_cluster-native-1.3.8-3.Final_redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_cluster-native-debuginfo-1.3.8-3.Final_redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_cluster-native-debuginfo-1.3.8-3.Final_redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_jk-ap24-1.2.46-1.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_jk-ap24-1.2.46-1.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_jk-debuginfo-1.2.46-1.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_jk-debuginfo-1.2.46-1.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_jk-manual-1.2.46-1.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_jk-manual-1.2.46-1.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_ldap-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_ldap-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_proxy_html-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_proxy_html-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_session-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_session-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_ssl-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_ssl-2.4.29-35.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-nghttp2-1.29.0-9.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-nghttp2-1.29.0-9.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-nghttp2-debuginfo-1.29.0-9.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-nghttp2-debuginfo-1.29.0-9.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-nghttp2-devel-1.29.0-9.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-nghttp2-devel-1.29.0-9.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-devel-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-devel-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-libs-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-libs-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-perl-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-perl-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-static-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-static-1.0.2n-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbcs-httpd24-runtime-1-6.jbcs.el6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"jbcs-httpd24-1-6.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apache-commons-daemon-jsvc-1.1.0-3.redhat_2.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apache-commons-daemon-jsvc-debuginfo-1.1.0-3.redhat_2.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-1.6.3-31.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-debuginfo-1.6.3-31.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-devel-1.6.3-31.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-debuginfo-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-devel-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-ldap-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-mysql-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-nss-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-odbc-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-openssl-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-pgsql-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-sqlite-1.6.1-24.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-debuginfo-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-devel-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbcs-httpd24-httpd-manual-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-selinux-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-httpd-tools-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_cluster-native-1.3.8-3.Final_redhat_2.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_cluster-native-debuginfo-1.3.8-3.Final_redhat_2.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_jk-ap24-1.2.46-1.redhat_1.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_jk-debuginfo-1.2.46-1.redhat_1.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_jk-manual-1.2.46-1.redhat_1.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_ldap-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_proxy_html-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_session-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-mod_ssl-2.4.29-35.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-nghttp2-1.29.0-9.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-nghttp2-debuginfo-1.29.0-9.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-nghttp2-devel-1.29.0-9.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-1.0.2n-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2n-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-devel-1.0.2n-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-libs-1.0.2n-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-perl-1.0.2n-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-static-1.0.2n-14.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jbcs-httpd24-runtime-1-6.jbcs.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbcs-httpd24 / jbcs-httpd24-apache-commons-daemon-jsvc / etc");
  }
}
