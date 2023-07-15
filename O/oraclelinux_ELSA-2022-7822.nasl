#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-7822.
##

include('compat.inc');

if (description)
{
  script_id(168133);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/23");

  script_cve_id("CVE-2022-2989", "CVE-2022-2990");

  script_name(english:"Oracle Linux 8 : container-tools:ol8 (ELSA-2022-7822)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-7822 advisory.

  - An incorrect handling of the supplementary groups in the Buildah container engine might lead to the
    sensitive information disclosure or possible data modification if an attacker has direct access to the
    affected container where supplementary groups are used to set access permissions and is able to execute a
    binary code in that container. (CVE-2022-2990)

  - An incorrect handling of the supplementary groups in the Podman container engine might lead to the
    sensitive information disclosure or possible data modification if an attacker has direct access to the
    affected container where supplementary groups are used to set access permissions and is able to execute a
    binary code in that container. (CVE-2022-2989)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-7822.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:aardvark-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:criu-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:crun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libslirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libslirp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netavark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oci-seccomp-bpf-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:udica");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/container-tools');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:ol8');
if ('ol8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module container-tools:' + module_ver);

var appstreams = {
    'container-tools:ol8': [
      {'reference':'aardvark-dns-1.1.0-5.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'aardvark-dns-1.1.0-5.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-1.27.2-2.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'buildah-1.27.2-2.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'buildah-tests-1.27.2-2.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'buildah-tests-1.27.2-2.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'cockpit-podman-53-1.module+el8.7.0+20877+e0f9ac15', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.1.4-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'conmon-2.1.4-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'container-selinux-2.189.0-1.module+el8.7.0+20877+e0f9ac15', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-1.1.1-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containernetworking-plugins-1.1.1-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-1-43.0.1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containers-common-1-43.0.1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'crit-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.5-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.5-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.9-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.9-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netavark-1.1.0-7.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'netavark-1.1.0-7.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-seccomp-bpf-hook-1.2.6-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.6-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-catatonit-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-catatonit-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-docker-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-gvproxy-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-gvproxy-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-plugins-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-plugins-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-remote-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-remote-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-tests-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'podman-tests-4.2.0-4.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'python3-criu-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-3.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-podman-4.2.1-1.module+el8.7.0+20877+e0f9ac15', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.1.4-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'runc-1.1.4-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-1.9.3-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-1.9.3-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.9.3-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.9.3-1.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'slirp4netns-1.2.0-2.module+el8.7.0+20877+e0f9ac15', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.2.0-2.module+el8.7.0+20877+e0f9ac15', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.6-3.module+el8.7.0+20877+e0f9ac15', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
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
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:ol8');

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aardvark-dns / buildah / buildah-tests / etc');
}
