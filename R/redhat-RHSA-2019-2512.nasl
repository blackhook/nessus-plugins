#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:2512. The text
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127992);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/24");

  script_cve_id("CVE-2019-0203");
  script_xref(name:"RHSA", value:"2019:2512");

  script_name(english:"RHEL 8 : subversion:1.10 (RHSA-2019:2512)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for the subversion:1.10 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.

Security Fix(es) :

* subversion: NULL pointer dereference in svnserve leading to an
unauthenticated remote DoS (CVE-2019-0203)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-0203"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0203");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libserf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libserf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:utf8proc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:utf8proc-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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

module_ver = get_kb_item('Host/RedHat/appstream/subversion');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module subversion:1.10');
if ('1.10' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module subversion:' + module_ver);

appstreams = {
    'subversion:1.10': [
      {'reference':'libserf-1.3.9-9.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'libserf-1.3.9-9.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'libserf-1.3.9-9.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'libserf-debugsource-1.3.9-9.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'libserf-debugsource-1.3.9-9.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'libserf-debugsource-1.3.9-9.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'mod_dav_svn-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'mod_dav_svn-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'mod_dav_svn-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'subversion-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'subversion-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'subversion-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'subversion-debugsource-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'subversion-debugsource-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'subversion-debugsource-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'subversion-devel-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'subversion-devel-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'subversion-devel-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'subversion-gnome-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'subversion-gnome-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'subversion-gnome-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'subversion-javahl-1.10.2-2.module+el8.0.0+3900+919b6753', 'release':'8'},
      {'reference':'subversion-libs-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'subversion-libs-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'subversion-libs-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'subversion-perl-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'subversion-perl-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'subversion-perl-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'subversion-tools-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'subversion-tools-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'subversion-tools-1.10.2-2.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'utf8proc-2.1.1-5.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'utf8proc-2.1.1-5.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'utf8proc-2.1.1-5.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'},
      {'reference':'utf8proc-debugsource-2.1.1-5.module+el8.0.0+3900+919b6753', 'cpu':'aarch64', 'release':'8'},
      {'reference':'utf8proc-debugsource-2.1.1-5.module+el8.0.0+3900+919b6753', 'cpu':'s390x', 'release':'8'},
      {'reference':'utf8proc-debugsource-2.1.1-5.module+el8.0.0+3900+919b6753', 'cpu':'x86_64', 'release':'8'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module subversion:1.10');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libserf / libserf-debugsource / mod_dav_svn / etc');
}
