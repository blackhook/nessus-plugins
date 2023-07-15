#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1389. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160030);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2021-3516",
    "CVE-2021-3517",
    "CVE-2021-3518",
    "CVE-2021-3537",
    "CVE-2021-3541",
    "CVE-2022-0778",
    "CVE-2022-22720",
    "CVE-2022-23308"
  );
  script_xref(name:"RHSA", value:"2022:1389");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"IAVA", value:"2021-A-0482");
  script_xref(name:"IAVA", value:"2022-A-0038");
  script_xref(name:"IAVA", value:"2022-A-0121-S");
  script_xref(name:"IAVA", value:"2022-A-0124-S");

  script_name(english:"RHEL 7 / 8 : Red Hat JBoss Core Services Apache HTTP Server 2.4.37 SP11 (RHSA-2022:1389)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:1389 advisory.

  - libxml2: Use-after-free in xmlEncodeEntitiesInternal() in entities.c (CVE-2021-3516)

  - libxml2: Heap-based buffer overflow in xmlEncodeEntitiesInternal() in entities.c (CVE-2021-3517)

  - libxml2: Use-after-free in xmlXIncludeDoProcess() in xinclude.c (CVE-2021-3518)

  - libxml2: NULL pointer dereference when post-validating mixed content parsed in recovery mode
    (CVE-2021-3537)

  - libxml2: Exponential entity expansion attack bypasses all existing protection mechanisms (CVE-2021-3541)

  - openssl: Infinite loop in BN_mod_sqrt() reachable when parsing certificates (CVE-2022-0778)

  - httpd: Errors encountered during the discarding of request body lead to HTTP request smuggling
    (CVE-2022-22720)

  - libxml2: Use-after-free of ID and IDREF attributes (CVE-2022-23308)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3516");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3517");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3518");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3537");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3541");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0778");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-22720");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23308");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1950515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1954225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1954232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1954242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1956522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2056913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2062202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2064321");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22720");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400, 416, 444, 476, 787, 835);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-util-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_jk-ap24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_jk-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-nghttp2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-chil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/jbcs/1/debug',
      'content/dist/layered/rhel8/x86_64/jbcs/1/os',
      'content/dist/layered/rhel8/x86_64/jbcs/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-apr-util-1.6.1-91.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-devel-1.6.1-91.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-ldap-1.6.1-91.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-mysql-1.6.1-91.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-nss-1.6.1-91.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-odbc-1.6.1-91.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-openssl-1.6.1-91.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-pgsql-1.6.1-91.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-sqlite-1.6.1-91.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-curl-7.78.0-3.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-2.4.37-80.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.37-80.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.37-80.el8jbcs', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.37-80.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.37-80.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-7.78.0-3.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-devel-7.78.0-3.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_cluster-native-1.3.16-10.Final_redhat_2.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_http2-1.15.7-22.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-ap24-1.2.48-29.redhat_1.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-manual-1.2.48-29.redhat_1.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.37-80.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_md-2.0.8-41.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.37-80.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_security-2.9.2-68.GA.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_session-2.4.37-80.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.37-80.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-1.39.2-41.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-devel-1.39.2-41.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-1.1.1g-11.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-chil-1.0.0-11.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-devel-1.1.1g-11.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-libs-1.1.1g-11.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-perl-1.1.1g-11.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-pkcs11-0.4.10-26.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-static-1.1.1g-11.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-apr-util-1.6.1-91.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-devel-1.6.1-91.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-ldap-1.6.1-91.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-mysql-1.6.1-91.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-nss-1.6.1-91.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-odbc-1.6.1-91.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-openssl-1.6.1-91.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-pgsql-1.6.1-91.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-util-sqlite-1.6.1-91.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-curl-7.78.0-3.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-2.4.37-80.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.37-80.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.37-80.jbcs.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.37-80.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.37-80.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-7.78.0-3.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-devel-7.78.0-3.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_cluster-native-1.3.16-10.Final_redhat_2.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_http2-1.15.7-22.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-ap24-1.2.48-29.redhat_1.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-manual-1.2.48-29.redhat_1.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.37-80.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_md-2.0.8-41.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.37-80.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_security-2.9.2-68.GA.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_session-2.4.37-80.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.37-80.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-1.39.2-41.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-devel-1.39.2-41.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-1.1.1g-11.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-chil-1.0.0-11.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-devel-1.1.1g-11.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-libs-1.1.1g-11.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-perl-1.1.1g-11.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-pkcs11-0.4.10-26.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-static-1.1.1g-11.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jbcs-httpd24-apr-util / jbcs-httpd24-apr-util-devel / etc');
}
