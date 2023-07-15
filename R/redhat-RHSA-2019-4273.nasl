#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:4273. The text
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132235);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-9512", "CVE-2019-9514");
  script_xref(name:"RHSA", value:"2019:4273");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"RHEL 8 : container-tools:1.0 (RHSA-2019:4273) (Ping Flood) (Reset Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for the container-tools:1.0 module is now available for Red
Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The container-tools module contains tools for working with containers,
notably podman, buildah, skopeo, and runc.

Security Fix(es) :

* HTTP/2: flood using PING frames results in unbounded memory growth
(CVE-2019-9512)

* HTTP/2: flood using HEADERS frames results in unbounded memory
growth (CVE-2019-9514)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:4273");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9512");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9514");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9512");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fuse-overlayfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-systemd-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-systemd-hook-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-umount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oci-umount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slirp4netns-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8.1");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/container-tools');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:1.0');
if ('1.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module container-tools:' + module_ver);

appstreams = {
    'container-tools:1.0': [
      {'reference':'buildah-1.5-6.gite94b4f9.module+el8.1.0+4908+72a45cef', 'cpu':'aarch64', 'release':'8'},
      {'reference':'buildah-1.5-6.gite94b4f9.module+el8.1.0+4908+72a45cef', 'cpu':'s390x', 'release':'8'},
      {'reference':'buildah-1.5-6.gite94b4f9.module+el8.1.0+4908+72a45cef', 'cpu':'x86_64', 'release':'8'},
      {'reference':'buildah-debugsource-1.5-6.gite94b4f9.module+el8.1.0+4908+72a45cef', 'cpu':'aarch64', 'release':'8'},
      {'reference':'buildah-debugsource-1.5-6.gite94b4f9.module+el8.1.0+4908+72a45cef', 'cpu':'s390x', 'release':'8'},
      {'reference':'buildah-debugsource-1.5-6.gite94b4f9.module+el8.1.0+4908+72a45cef', 'cpu':'x86_64', 'release':'8'},
      {'reference':'container-selinux-2.94-1.git1e99f1d.module+el8.1.0+3468+011f0ab0', 'release':'8', 'epoch':'2'},
      {'reference':'containernetworking-plugins-0.7.4-4.git9ebe139.module+el8.1.0+4908+72a45cef', 'cpu':'aarch64', 'release':'8'},
      {'reference':'containernetworking-plugins-0.7.4-4.git9ebe139.module+el8.1.0+4908+72a45cef', 'cpu':'s390x', 'release':'8'},
      {'reference':'containernetworking-plugins-0.7.4-4.git9ebe139.module+el8.1.0+4908+72a45cef', 'cpu':'x86_64', 'release':'8'},
      {'reference':'containernetworking-plugins-debugsource-0.7.4-4.git9ebe139.module+el8.1.0+4908+72a45cef', 'cpu':'aarch64', 'release':'8'},
      {'reference':'containernetworking-plugins-debugsource-0.7.4-4.git9ebe139.module+el8.1.0+4908+72a45cef', 'cpu':'s390x', 'release':'8'},
      {'reference':'containernetworking-plugins-debugsource-0.7.4-4.git9ebe139.module+el8.1.0+4908+72a45cef', 'cpu':'x86_64', 'release':'8'},
      {'reference':'containers-common-0.1.32-6.git1715c90.module+el8.1.0+4903+9bde5d6c', 'cpu':'aarch64', 'release':'8', 'epoch':'1'},
      {'reference':'containers-common-0.1.32-6.git1715c90.module+el8.1.0+4903+9bde5d6c', 'cpu':'s390x', 'release':'8', 'epoch':'1'},
      {'reference':'containers-common-0.1.32-6.git1715c90.module+el8.1.0+4903+9bde5d6c', 'cpu':'x86_64', 'release':'8', 'epoch':'1'},
      {'reference':'fuse-overlayfs-0.3-5.module+el8.1.0+3468+011f0ab0', 'cpu':'aarch64', 'release':'8'},
      {'reference':'fuse-overlayfs-0.3-5.module+el8.1.0+3468+011f0ab0', 'cpu':'s390x', 'release':'8'},
      {'reference':'fuse-overlayfs-0.3-5.module+el8.1.0+3468+011f0ab0', 'cpu':'x86_64', 'release':'8'},
      {'reference':'fuse-overlayfs-debugsource-0.3-5.module+el8.1.0+3468+011f0ab0', 'cpu':'aarch64', 'release':'8'},
      {'reference':'fuse-overlayfs-debugsource-0.3-5.module+el8.1.0+3468+011f0ab0', 'cpu':'s390x', 'release':'8'},
      {'reference':'fuse-overlayfs-debugsource-0.3-5.module+el8.1.0+3468+011f0ab0', 'cpu':'x86_64', 'release':'8'},
      {'reference':'oci-systemd-hook-0.1.15-2.git2d0b8a3.module+el8.1.0+3468+011f0ab0', 'cpu':'aarch64', 'release':'8', 'epoch':'1'},
      {'reference':'oci-systemd-hook-0.1.15-2.git2d0b8a3.module+el8.1.0+3468+011f0ab0', 'cpu':'s390x', 'release':'8', 'epoch':'1'},
      {'reference':'oci-systemd-hook-0.1.15-2.git2d0b8a3.module+el8.1.0+3468+011f0ab0', 'cpu':'x86_64', 'release':'8', 'epoch':'1'},
      {'reference':'oci-systemd-hook-debugsource-0.1.15-2.git2d0b8a3.module+el8.1.0+3468+011f0ab0', 'cpu':'aarch64', 'release':'8', 'epoch':'1'},
      {'reference':'oci-systemd-hook-debugsource-0.1.15-2.git2d0b8a3.module+el8.1.0+3468+011f0ab0', 'cpu':'s390x', 'release':'8', 'epoch':'1'},
      {'reference':'oci-systemd-hook-debugsource-0.1.15-2.git2d0b8a3.module+el8.1.0+3468+011f0ab0', 'cpu':'x86_64', 'release':'8', 'epoch':'1'},
      {'reference':'oci-umount-2.3.4-2.git87f9237.module+el8.1.0+3468+011f0ab0', 'cpu':'aarch64', 'release':'8', 'epoch':'2'},
      {'reference':'oci-umount-2.3.4-2.git87f9237.module+el8.1.0+3468+011f0ab0', 'cpu':'s390x', 'release':'8', 'epoch':'2'},
      {'reference':'oci-umount-2.3.4-2.git87f9237.module+el8.1.0+3468+011f0ab0', 'cpu':'x86_64', 'release':'8', 'epoch':'2'},
      {'reference':'oci-umount-debugsource-2.3.4-2.git87f9237.module+el8.1.0+3468+011f0ab0', 'cpu':'aarch64', 'release':'8', 'epoch':'2'},
      {'reference':'oci-umount-debugsource-2.3.4-2.git87f9237.module+el8.1.0+3468+011f0ab0', 'cpu':'s390x', 'release':'8', 'epoch':'2'},
      {'reference':'oci-umount-debugsource-2.3.4-2.git87f9237.module+el8.1.0+3468+011f0ab0', 'cpu':'x86_64', 'release':'8', 'epoch':'2'},
      {'reference':'podman-1.0.0-4.git921f98f.module+el8.1.0+4908+72a45cef', 'cpu':'aarch64', 'release':'8'},
      {'reference':'podman-1.0.0-4.git921f98f.module+el8.1.0+4908+72a45cef', 'cpu':'s390x', 'release':'8'},
      {'reference':'podman-1.0.0-4.git921f98f.module+el8.1.0+4908+72a45cef', 'cpu':'x86_64', 'release':'8'},
      {'reference':'podman-debugsource-1.0.0-4.git921f98f.module+el8.1.0+4908+72a45cef', 'cpu':'aarch64', 'release':'8'},
      {'reference':'podman-debugsource-1.0.0-4.git921f98f.module+el8.1.0+4908+72a45cef', 'cpu':'s390x', 'release':'8'},
      {'reference':'podman-debugsource-1.0.0-4.git921f98f.module+el8.1.0+4908+72a45cef', 'cpu':'x86_64', 'release':'8'},
      {'reference':'podman-docker-1.0.0-4.git921f98f.module+el8.1.0+4908+72a45cef', 'release':'8'},
      {'reference':'runc-1.0.0-56.rc5.dev.git2abd837.module+el8.1.0+4908+72a45cef', 'cpu':'aarch64', 'release':'8'},
      {'reference':'runc-1.0.0-56.rc5.dev.git2abd837.module+el8.1.0+4908+72a45cef', 'cpu':'s390x', 'release':'8'},
      {'reference':'runc-1.0.0-56.rc5.dev.git2abd837.module+el8.1.0+4908+72a45cef', 'cpu':'x86_64', 'release':'8'},
      {'reference':'runc-debugsource-1.0.0-56.rc5.dev.git2abd837.module+el8.1.0+4908+72a45cef', 'cpu':'aarch64', 'release':'8'},
      {'reference':'runc-debugsource-1.0.0-56.rc5.dev.git2abd837.module+el8.1.0+4908+72a45cef', 'cpu':'s390x', 'release':'8'},
      {'reference':'runc-debugsource-1.0.0-56.rc5.dev.git2abd837.module+el8.1.0+4908+72a45cef', 'cpu':'x86_64', 'release':'8'},
      {'reference':'skopeo-0.1.32-6.git1715c90.module+el8.1.0+4903+9bde5d6c', 'cpu':'aarch64', 'release':'8', 'epoch':'1'},
      {'reference':'skopeo-0.1.32-6.git1715c90.module+el8.1.0+4903+9bde5d6c', 'cpu':'s390x', 'release':'8', 'epoch':'1'},
      {'reference':'skopeo-0.1.32-6.git1715c90.module+el8.1.0+4903+9bde5d6c', 'cpu':'x86_64', 'release':'8', 'epoch':'1'},
      {'reference':'skopeo-debugsource-0.1.32-6.git1715c90.module+el8.1.0+4903+9bde5d6c', 'cpu':'aarch64', 'release':'8', 'epoch':'1'},
      {'reference':'skopeo-debugsource-0.1.32-6.git1715c90.module+el8.1.0+4903+9bde5d6c', 'cpu':'s390x', 'release':'8', 'epoch':'1'},
      {'reference':'skopeo-debugsource-0.1.32-6.git1715c90.module+el8.1.0+4903+9bde5d6c', 'cpu':'x86_64', 'release':'8', 'epoch':'1'},
      {'reference':'slirp4netns-0.1-3.dev.gitc4e1bc5.module+el8.1.0+4308+9d868e48', 'cpu':'aarch64', 'release':'8'},
      {'reference':'slirp4netns-0.1-3.dev.gitc4e1bc5.module+el8.1.0+4308+9d868e48', 'cpu':'s390x', 'release':'8'},
      {'reference':'slirp4netns-0.1-3.dev.gitc4e1bc5.module+el8.1.0+4308+9d868e48', 'cpu':'x86_64', 'release':'8'},
      {'reference':'slirp4netns-debugsource-0.1-3.dev.gitc4e1bc5.module+el8.1.0+4308+9d868e48', 'cpu':'aarch64', 'release':'8'},
      {'reference':'slirp4netns-debugsource-0.1-3.dev.gitc4e1bc5.module+el8.1.0+4308+9d868e48', 'cpu':'s390x', 'release':'8'},
      {'reference':'slirp4netns-debugsource-0.1-3.dev.gitc4e1bc5.module+el8.1.0+4308+9d868e48', 'cpu':'x86_64', 'release':'8'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:1.0');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-debugsource / container-selinux / etc');
}
