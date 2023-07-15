#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2022:7529. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167185);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-1705",
    "CVE-2022-1708",
    "CVE-2022-1962",
    "CVE-2022-21698",
    "CVE-2022-28131",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-32148"
  );
  script_xref(name:"RHSA", value:"2022:7529");

  script_name(english:"CentOS 8 : container-tools:3.0 (CESA-2022:7529)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2022:7529 advisory.

  - golang: net/http: improper sanitization of Transfer-Encoding header (CVE-2022-1705)

  - cri-o: memory exhaustion on the node when access to the kube api (CVE-2022-1708)

  - golang: go/parser: stack exhaustion in all Parse* functions (CVE-2022-1962)

  - prometheus/client_golang: Denial of service using InstrumentHandlerCounter (CVE-2022-21698)

  - golang: encoding/xml: stack exhaustion in Decoder.Skip (CVE-2022-28131)

  - golang: io/fs: stack exhaustion in Glob (CVE-2022-30630)

  - golang: compress/gzip: stack exhaustion in Reader.Read (CVE-2022-30631)

  - golang: path/filepath: stack exhaustion in Glob (CVE-2022-30632)

  - golang: encoding/xml: stack exhaustion in Unmarshal (CVE-2022-30633)

  - golang: net/http/httputil: NewSingleHostReverseProxy - omit X-Forwarded-For not working (CVE-2022-32148)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:7529");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1708");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:crun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libslirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libslirp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:oci-seccomp-bpf-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:udica");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/container-tools');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:3.0');
if ('3.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module container-tools:' + module_ver);

var appstreams = {
    'container-tools:3.0': [
      {'reference':'buildah-1.19.9-6.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-1.19.9-6.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-tests-1.19.9-6.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-tests-1.19.9-6.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cockpit-podman-29-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'cockpit-podman-29-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.0.26-3.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'conmon-2.0.26-3.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'container-selinux-2.189.0-1.module_el8.7.0+1216+b022c01d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'container-selinux-2.189.0-1.module_el8.7.0+1216+b022c01d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.9.1-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.9.1-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containers-common-1.2.4-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containers-common-1.2.4-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-0.18-3.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-0.18-3.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-3.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-3.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-catatonit-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-catatonit-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-docker-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-docker-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-plugins-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-plugins-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-remote-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-remote-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-tests-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-tests-3.0.1-13.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'skopeo-1.2.4-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'skopeo-1.2.4-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'skopeo-tests-1.2.4-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'skopeo-tests-1.2.4-2.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.4-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.4-1.module_el8.7.0+1217+ea57d1f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:3.0');

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-tests / cockpit-podman / conmon / container-selinux / etc');
}
