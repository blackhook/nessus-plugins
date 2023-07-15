##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2644. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(137705);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2018-20843",
    "CVE-2019-0196",
    "CVE-2019-0197",
    "CVE-2019-15903",
    "CVE-2019-19956",
    "CVE-2019-20388",
    "CVE-2020-1934",
    "CVE-2020-7595",
    "CVE-2020-11080"
  );
  script_bugtraq_id(107665, 107669);
  script_xref(name:"RHSA", value:"2020:2644");
  script_xref(name:"IAVA", value:"2020-A-0326");
  script_xref(name:"IAVA", value:"2019-A-0098-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Core Services Apache HTTP Server 2.4.37 SP3 (RHSA-2020:2644)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2644 advisory.

  - expat: large number of colons in input makes parser consume high amount of resources, leading to DoS
    (CVE-2018-20843)

  - httpd: mod_http2: read-after-free on a string compare (CVE-2019-0196)

  - httpd: mod_http2: possible crash on late upgrade (CVE-2019-0197)

  - expat: heap-based buffer over-read via crafted XML input (CVE-2019-15903)

  - libxml2: memory leak in xmlParseBalancedChunkMemoryRecover in parser.c (CVE-2019-19956)

  - libxml2: memory leak in xmlSchemaPreRun in xmlschemas.c (CVE-2019-20388)

  - nghttp2: overly large SETTINGS frames can lead to DoS (CVE-2020-11080)

  - httpd: mod_proxy_ftp use of uninitialized value (CVE-2020-1934)

  - libxml2: infinite loop in xmlStringLenDecodeEntities in some end-of-file situations (CVE-2020-7595)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20843");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-0196");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-0197");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15903");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19956");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20388");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1934");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7595");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11080");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1695030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1695042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1723723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1752592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1788856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1799734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1799786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1820772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844929");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 400, 401, 416, 444, 456, 770, 772, 835);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-pkcs11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jbcs/1/debug',
      'content/dist/rhel/server/6/6Server/i386/jbcs/1/os',
      'content/dist/rhel/server/6/6Server/i386/jbcs/1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbcs/1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbcs/1/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbcs/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-curl-7.64.1-36.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-curl-7.64.1-36.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-2.4.37-57.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-2.4.37-57.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.37-57.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.37-57.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.37-57.jbcs.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.37-57.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.37-57.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.37-57.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.37-57.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-7.64.1-36.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-7.64.1-36.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-devel-7.64.1-36.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-devel-7.64.1-36.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_cluster-native-1.3.14-4.Final_redhat_2.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_cluster-native-1.3.14-4.Final_redhat_2.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_http2-1.15.7-3.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_http2-1.15.7-3.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-ap24-1.2.48-4.redhat_1.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-ap24-1.2.48-4.redhat_1.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-manual-1.2.48-4.redhat_1.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-manual-1.2.48-4.redhat_1.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.37-57.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.37-57.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_md-2.0.8-24.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_md-2.0.8-24.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.37-57.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.37-57.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_security-2.9.2-51.GA.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_security-2.9.2-51.GA.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_session-2.4.37-57.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_session-2.4.37-57.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.37-57.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.37-57.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-1.39.2-25.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-1.39.2-25.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-devel-1.39.2-25.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-devel-1.39.2-25.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-curl-7.64.1-36.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-2.4.37-57.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.37-57.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.37-57.jbcs.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.37-57.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.37-57.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-7.64.1-36.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-libcurl-devel-7.64.1-36.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_cluster-native-1.3.14-4.Final_redhat_2.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_http2-1.15.7-3.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-ap24-1.2.48-4.redhat_1.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_jk-manual-1.2.48-4.redhat_1.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.37-57.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_md-2.0.8-24.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.37-57.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_security-2.9.2-51.GA.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_session-2.4.37-57.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.37-57.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-1.39.2-25.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-nghttp2-devel-1.39.2-25.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-pkcs11-0.4.10-7.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jbcs-httpd24-curl / jbcs-httpd24-httpd / jbcs-httpd24-httpd-devel / etc');
}
