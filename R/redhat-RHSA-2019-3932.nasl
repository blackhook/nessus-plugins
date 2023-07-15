#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3932. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131215);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-0734",
    "CVE-2018-0737",
    "CVE-2018-17189",
    "CVE-2018-17199",
    "CVE-2018-5407",
    "CVE-2019-0196",
    "CVE-2019-0197",
    "CVE-2019-0217",
    "CVE-2019-9511",
    "CVE-2019-9513",
    "CVE-2019-9516",
    "CVE-2019-9517"
  );
  script_xref(name:"RHSA", value:"2019:3932");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"RHEL 6 : JBoss Core Services (RHSA-2019:3932) (0-Length Headers Leak) (Data Dribble) (Internal Data Buffering) (Resource Loop)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated packages that provide Red Hat JBoss Core Services Pack Apache
Server 2.4.37 and fix several bugs, and add various enhancements are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

This release adds the new Apache HTTP Server 2.4.37 packages that are
part of the JBoss Core Services offering.

This release serves as a replacement for Red Hat JBoss Core Services
Pack Apache Server 2.4.29 and includes bug fixes and enhancements.
Refer to the Release Notes for information on the most significant bug
fixes and enhancements included in this release.

Security Fix(es) :

* openssl: RSA key generation cache timing vulnerability in
crypto/rsa/ rsa_gen.c allows attackers to recover private keys
(CVE-2018-0737) * openssl: timing side channel attack in the DSA
signature algorithm (CVE-2018-0734) * mod_auth_digest: access control
bypass due to race condition (CVE-2019-0217) * openssl: Side-channel
vulnerability on SMT/ Hyper-Threading architectures (PortSmash)
(CVE-2018-5407) * mod_session_cookie does not respect expiry time
(CVE-2018-17199) * mod_http2: DoS via slow, unneeded request bodies
(CVE-2018-17189) * mod_http2: possible crash on late upgrade
(CVE-2019-0197) * mod_http2: read-after-free on a string compare
(CVE-2019-0196) * nghttp2: HTTP/2: large amount of data request leads
to denial of service (CVE-2019-9511) * nghttp2: HTTP/2: flood using
PRIORITY frames resulting in excessive resource consumption
(CVE-2019-9513) * mod_http2: HTTP/2: 0-length headers leads to denial
of service (CVE-2019-9516) * mod_http2: HTTP/2: request for large
response leads to denial of service (CVE-2019-9517)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3932");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-0734");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-0737");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-5407");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-17189");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-17199");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-0196");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-0197");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-0217");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9511");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9513");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9516");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9517");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-brotli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-brotli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-brotli-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-jansson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-jansson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-jansson-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_cluster-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_jk-ap24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_jk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_jk-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_security-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3932";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-1.6.3-63.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-1.6.3-63.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-debuginfo-1.6.3-63.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-debuginfo-1.6.3-63.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-devel-1.6.3-63.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-devel-1.6.3-63.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-debuginfo-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-debuginfo-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-devel-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-devel-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-ldap-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-ldap-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-mysql-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-mysql-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-nss-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-nss-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-odbc-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-odbc-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-openssl-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-openssl-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-pgsql-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-pgsql-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-apr-util-sqlite-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-apr-util-sqlite-1.6.1-48.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-brotli-1.0.6-7.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-brotli-1.0.6-7.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-brotli-debuginfo-1.0.6-7.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-brotli-debuginfo-1.0.6-7.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-brotli-devel-1.0.6-7.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-brotli-devel-1.0.6-7.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-curl-7.64.1-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-curl-7.64.1-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-curl-debuginfo-7.64.1-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-curl-debuginfo-7.64.1-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-debuginfo-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-debuginfo-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-devel-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-devel-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbcs-httpd24-httpd-manual-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-selinux-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-selinux-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-httpd-tools-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-httpd-tools-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-jansson-2.11-20.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-jansson-2.11-20.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-jansson-debuginfo-2.11-20.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-jansson-debuginfo-2.11-20.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-jansson-devel-2.11-20.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-jansson-devel-2.11-20.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-libcurl-7.64.1-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-libcurl-7.64.1-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-libcurl-devel-7.64.1-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-libcurl-devel-7.64.1-14.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_cluster-native-1.3.12-9.Final_redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_cluster-native-1.3.12-9.Final_redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_cluster-native-debuginfo-1.3.12-9.Final_redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_cluster-native-debuginfo-1.3.12-9.Final_redhat_2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_jk-ap24-1.2.46-22.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_jk-ap24-1.2.46-22.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_jk-debuginfo-1.2.46-22.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_jk-debuginfo-1.2.46-22.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_jk-manual-1.2.46-22.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_jk-manual-1.2.46-22.redhat_1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_ldap-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_ldap-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_md-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_md-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_proxy_html-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_proxy_html-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_security-2.9.2-16.GA.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_security-2.9.2-16.GA.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_security-debuginfo-2.9.2-16.GA.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_security-debuginfo-2.9.2-16.GA.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_session-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_session-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-mod_ssl-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-mod_ssl-2.4.37-33.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-nghttp2-1.39.2-4.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-nghttp2-1.39.2-4.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-nghttp2-debuginfo-1.39.2-4.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-nghttp2-debuginfo-1.39.2-4.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-nghttp2-devel-1.39.2-4.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-nghttp2-devel-1.39.2-4.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-debuginfo-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-debuginfo-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-devel-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-devel-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-libs-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-libs-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-perl-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-perl-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-static-1.1.1-25.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-static-1.1.1-25.jbcs.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbcs-httpd24-apr / jbcs-httpd24-apr-debuginfo / etc");
  }
}
