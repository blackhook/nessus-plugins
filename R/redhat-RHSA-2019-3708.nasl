#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:3708. The text
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130575);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/24");

  script_cve_id("CVE-2019-2510", "CVE-2019-2537", "CVE-2019-2614", "CVE-2019-2627", "CVE-2019-2628", "CVE-2019-2737", "CVE-2019-2739", "CVE-2019-2740", "CVE-2019-2758", "CVE-2019-2805");
  script_xref(name:"RHSA", value:"2019:3708");

  script_name(english:"RHEL 8 : mariadb:10.3 (RHSA-2019:3708)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for the mariadb:10.3 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

MariaDB is a multi-user, multi-threaded SQL database server that is
binary compatible with MySQL.

The following packages have been upgraded to a later upstream version:
mariadb (10.3.17), galera (25.3.26). (BZ#1701687, BZ#1711265,
BZ#1741358)

Security Fix(es) :

* mysql: InnoDB unspecified vulnerability (CPU Jan 2019)
(CVE-2019-2510)

* mysql: Server: DDL unspecified vulnerability (CPU Jan 2019)
(CVE-2019-2537)

* mysql: Server: Replication unspecified vulnerability (CPU Apr 2019)
(CVE-2019-2614)

* mysql: Server: Security: Privileges unspecified vulnerability (CPU
Apr 2019) (CVE-2019-2627)

* mysql: InnoDB unspecified vulnerability (CPU Apr 2019)
(CVE-2019-2628)

* mysql: Server: Pluggable Auth unspecified vulnerability (CPU Jul
2019) (CVE-2019-2737)

* mysql: Server: Security: Privileges unspecified vulnerability (CPU
Jul 2019) (CVE-2019-2739)

* mysql: Server: XML unspecified vulnerability (CPU Jul 2019)
(CVE-2019-2740)

* mysql: InnoDB unspecified vulnerability (CPU Jul 2019)
(CVE-2019-2758)

* mysql: Server: Parser unspecified vulnerability (CPU Jul 2019)
(CVE-2019-2805)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 8.1 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?774148ae"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:3708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2805"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2758");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:Judy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:Judy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:Judy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:asio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:galera-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-server-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

appstreams = {
    'mariadb-devel:10.3': [
      {'reference':'asio-devel-1.10.8-7.module+el8+2765+cfa4f87b', 'cpu':'aarch64', 'release':'8'},
      {'reference':'asio-devel-1.10.8-7.module+el8+2765+cfa4f87b', 'cpu':'i686', 'release':'8'},
      {'reference':'asio-devel-1.10.8-7.module+el8+2765+cfa4f87b', 'cpu':'s390x', 'release':'8'},
      {'reference':'asio-devel-1.10.8-7.module+el8+2765+cfa4f87b', 'cpu':'x86_64', 'release':'8'},
      {'reference':'galera-25.3.26-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8'},
      {'reference':'galera-debugsource-25.3.26-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8'},
      {'reference':'Judy-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'i686', 'release':'8'},
      {'reference':'Judy-debugsource-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'i686', 'release':'8'},
      {'reference':'Judy-devel-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'aarch64', 'release':'8'},
      {'reference':'Judy-devel-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'i686', 'release':'8'},
      {'reference':'Judy-devel-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'s390x', 'release':'8'},
      {'reference':'Judy-devel-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'x86_64', 'release':'8'},
      {'reference':'mariadb-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-backup-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-common-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-debugsource-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-embedded-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-test-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'epoch':'3'}
    ],
    'mariadb:10.3': [
      {'reference':'galera-25.3.26-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8'},
      {'reference':'galera-25.3.26-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8'},
      {'reference':'galera-25.3.26-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8'},
      {'reference':'galera-debugsource-25.3.26-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8'},
      {'reference':'galera-debugsource-25.3.26-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8'},
      {'reference':'galera-debugsource-25.3.26-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8'},
      {'reference':'Judy-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'aarch64', 'release':'8'},
      {'reference':'Judy-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'s390x', 'release':'8'},
      {'reference':'Judy-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'x86_64', 'release':'8'},
      {'reference':'Judy-debugsource-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'aarch64', 'release':'8'},
      {'reference':'Judy-debugsource-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'s390x', 'release':'8'},
      {'reference':'Judy-debugsource-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'x86_64', 'release':'8'},
      {'reference':'mariadb-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-backup-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-backup-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-backup-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-common-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-common-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-common-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-debugsource-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-debugsource-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-debugsource-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-embedded-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-embedded-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-embedded-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-test-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'aarch64', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-test-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'s390x', 'release':'8', 'epoch':'3'},
      {'reference':'mariadb-test-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'x86_64', 'release':'8', 'epoch':'3'}
    ],
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'RHEL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb-devel:10.3 / mariadb:10.3');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Judy / Judy-debugsource / Judy-devel / etc');
}
