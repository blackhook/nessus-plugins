##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1337. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(135235);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-1547",
    "CVE-2019-1549",
    "CVE-2019-1563",
    "CVE-2019-10081",
    "CVE-2019-10082",
    "CVE-2019-10092",
    "CVE-2019-10097",
    "CVE-2019-10098"
  );
  script_xref(name:"RHSA", value:"2020:1337");
  script_xref(name:"IAVA", value:"2020-A-0022");
  script_xref(name:"IAVA", value:"2020-A-0140");
  script_xref(name:"IAVA", value:"2019-A-0303-S");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Core Services Apache HTTP Server 2.4.37 SP2 (RHSA-2020:1337)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1337 advisory.

  - httpd: memory corruption on early pushes (CVE-2019-10081)

  - httpd: read-after-free in h2 connection shutdown (CVE-2019-10082)

  - httpd: limited cross-site scripting in mod_proxy error page (CVE-2019-10092)

  - httpd: null-pointer dereference in mod_remoteip (CVE-2019-10097)

  - httpd: mod_rewrite potential open redirect (CVE-2019-10098)

  - openssl: side-channel weak encryption vulnerability (CVE-2019-1547)

  - openssl: information disclosure in fork() (CVE-2019-1549)

  - openssl: information disclosure in PKCS7_dataDecode and CMS_decrypt_set1_pkey (CVE-2019-1563)

  - httpd: mod_rewrite configurations vulnerable to open redirect (CVE-2020-1927)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-1547");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-1549");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-1563");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10081");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10082");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10092");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10097");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10098");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1927");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1743956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1743959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1743966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1743974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1743996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1752090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1752095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1752100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1820761");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 120, 200, 400, 416, 601, 602);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-brotli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-brotli-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
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
      {'reference':'jbcs-httpd24-apr-1.6.3-86.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-1.6.3-86.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-devel-1.6.3-86.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-devel-1.6.3-86.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-brotli-1.0.6-21.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-brotli-1.0.6-21.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-brotli-devel-1.0.6-21.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-brotli-devel-1.0.6-21.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-2.4.37-52.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-2.4.37-52.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.37-52.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.37-52.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.37-52.jbcs.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.37-52.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.37-52.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.37-52.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.37-52.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_cluster-native-1.3.12-41.Final_redhat_2.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_cluster-native-1.3.12-41.Final_redhat_2.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_http2-1.11.3-22.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_http2-1.11.3-22.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.37-52.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.37-52.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.37-52.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.37-52.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_session-2.4.37-52.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_session-2.4.37-52.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.37-52.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.37-52.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-1.1.1c-16.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-1.1.1c-16.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-devel-1.1.1c-16.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-devel-1.1.1c-16.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-libs-1.1.1c-16.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-libs-1.1.1c-16.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-perl-1.1.1c-16.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-perl-1.1.1c-16.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-static-1.1.1c-16.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-static-1.1.1c-16.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-apr-1.6.3-86.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-apr-devel-1.6.3-86.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-brotli-1.0.6-21.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-brotli-devel-1.0.6-21.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-2.4.37-52.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.37-52.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.37-52.jbcs.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.37-52.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.37-52.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_cluster-native-1.3.12-41.Final_redhat_2.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_http2-1.11.3-22.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.37-52.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.37-52.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_session-2.4.37-52.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.37-52.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-1.1.1c-16.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-devel-1.1.1c-16.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-libs-1.1.1c-16.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-perl-1.1.1c-16.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'},
      {'reference':'jbcs-httpd24-openssl-static-1.1.1c-16.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jbcs-httpd24-apr / jbcs-httpd24-apr-devel / jbcs-httpd24-brotli / etc');
}
