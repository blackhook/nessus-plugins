#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:2370.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157811);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2021-30465");
  script_xref(name:"RLSA", value:"2021:2370");

  script_name(english:"Rocky Linux 8 : container-tools:3.0 (RLSA-2021:2370)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2021:2370 advisory.

  - runc before 1.0.0-rc95 allows a Container Filesystem Breakout via Directory Traversal. To exploit the
    vulnerability, an attacker must be able to create multiple containers with a fairly specific mount
    configuration. The problem occurs via a symlink-exchange attack that relies on a race condition.
    (CVE-2021-30465)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:2370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1954736");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crun-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crun-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-seccomp-bpf-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-seccomp-bpf-hook-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-seccomp-bpf-hook-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-catatonit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-podman-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:udica");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'buildah-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-1.11'},
    {'reference':'buildah-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-1.11'},
    {'reference':'buildah-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-1.19'},
    {'reference':'buildah-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-1.19'},
    {'reference':'buildah-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-1.19'},
    {'reference':'buildah-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-1.19'},
    {'reference':'buildah-debuginfo-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debuginfo-1.11'},
    {'reference':'buildah-debuginfo-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debuginfo-1.11'},
    {'reference':'buildah-debuginfo-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debuginfo-1.19'},
    {'reference':'buildah-debuginfo-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debuginfo-1.19'},
    {'reference':'buildah-debuginfo-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debuginfo-1.19'},
    {'reference':'buildah-debuginfo-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debuginfo-1.19'},
    {'reference':'buildah-debugsource-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debugsource-1.11'},
    {'reference':'buildah-debugsource-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debugsource-1.11'},
    {'reference':'buildah-debugsource-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debugsource-1.19'},
    {'reference':'buildah-debugsource-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debugsource-1.19'},
    {'reference':'buildah-debugsource-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debugsource-1.19'},
    {'reference':'buildah-debugsource-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-debugsource-1.19'},
    {'reference':'buildah-tests-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-1.11'},
    {'reference':'buildah-tests-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-1.11'},
    {'reference':'buildah-tests-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-1.19'},
    {'reference':'buildah-tests-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-1.19'},
    {'reference':'buildah-tests-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-1.19'},
    {'reference':'buildah-tests-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-1.19'},
    {'reference':'buildah-tests-debuginfo-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-debuginfo-1.11'},
    {'reference':'buildah-tests-debuginfo-1.11.6-8.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-debuginfo-1.11'},
    {'reference':'buildah-tests-debuginfo-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-debuginfo-1.19'},
    {'reference':'buildah-tests-debuginfo-1.19.7-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-debuginfo-1.19'},
    {'reference':'buildah-tests-debuginfo-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-debuginfo-1.19'},
    {'reference':'buildah-tests-debuginfo-1.19.7-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'buildah-tests-debuginfo-1.19'},
    {'reference':'cockpit-podman-11-1.module+el8.4.0+559+c02fa3b2', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'cockpit-podman-11'},
    {'reference':'cockpit-podman-29-2.module+el8.4.0+556+40122d08', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cockpit-podman-29'},
    {'reference':'conmon-2.0.15-1.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'conmon-2.0'},
    {'reference':'conmon-2.0.15-1.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'conmon-2.0'},
    {'reference':'conmon-2.0.26-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'conmon-2.0'},
    {'reference':'conmon-2.0.26-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'conmon-2.0'},
    {'reference':'conmon-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'conmon-2.0'},
    {'reference':'conmon-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'conmon-2.0'},
    {'reference':'conmon-debuginfo-2.0.26-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'conmon-debuginfo-2.0.26-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'conmon-debuginfo-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'conmon-debuginfo-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'conmon-debugsource-2.0.26-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'conmon-debugsource-2.0.26-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'conmon-debugsource-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'conmon-debugsource-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'container-selinux-2.130.0-1.module+el8.4.0+559+c02fa3b2', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'container-selinux-2.130'},
    {'reference':'container-selinux-2.158.0-1.module+el8.4.0+558+7340b765', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'container-selinux-2.158'},
    {'reference':'container-selinux-2.162.0-1.module+el8.4.0+556+40122d08', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'container-selinux-2.162'},
    {'reference':'containernetworking-plugins-0.8.3-4.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-0.8'},
    {'reference':'containernetworking-plugins-0.8.3-4.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-0.8'},
    {'reference':'containernetworking-plugins-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-0.9'},
    {'reference':'containernetworking-plugins-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-0.9'},
    {'reference':'containernetworking-plugins-debuginfo-0.8.3-4.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-debuginfo-0.8'},
    {'reference':'containernetworking-plugins-debuginfo-0.8.3-4.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-debuginfo-0.8'},
    {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-debuginfo-0.9'},
    {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-debuginfo-0.9'},
    {'reference':'containernetworking-plugins-debugsource-0.8.3-4.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-debugsource-0.8'},
    {'reference':'containernetworking-plugins-debugsource-0.8.3-4.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-debugsource-0.8'},
    {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-debugsource-0.9'},
    {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containernetworking-plugins-debugsource-0.9'},
    {'reference':'containers-common-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containers-common-0'},
    {'reference':'containers-common-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containers-common-0'},
    {'reference':'containers-common-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containers-common-1.2'},
    {'reference':'containers-common-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containers-common-1.2'},
    {'reference':'containers-common-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containers-common-1.2'},
    {'reference':'containers-common-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'containers-common-1.2'},
    {'reference':'crit-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'crit-3.12'},
    {'reference':'crit-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'crit-3.12'},
    {'reference':'crit-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'crit-3.15'},
    {'reference':'crit-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'crit-3.15'},
    {'reference':'criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-3.12'},
    {'reference':'criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-3.12'},
    {'reference':'criu-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-3.15'},
    {'reference':'criu-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-3.15'},
    {'reference':'criu-debuginfo-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-debuginfo-3.12'},
    {'reference':'criu-debuginfo-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-debuginfo-3.12'},
    {'reference':'criu-debuginfo-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-debuginfo-3.15'},
    {'reference':'criu-debuginfo-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-debuginfo-3.15'},
    {'reference':'criu-debugsource-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-debugsource-3.12'},
    {'reference':'criu-debugsource-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-debugsource-3.12'},
    {'reference':'criu-debugsource-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-debugsource-3.15'},
    {'reference':'criu-debugsource-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'criu-debugsource-3.15'},
    {'reference':'crun-0.18-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-0.18-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debuginfo-0.18-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debuginfo-0.18-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debugsource-0.18-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debugsource-0.18-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-0.7.8-1.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-0'},
    {'reference':'fuse-overlayfs-0.7.8-1.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-0'},
    {'reference':'fuse-overlayfs-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-1.4'},
    {'reference':'fuse-overlayfs-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-1.4'},
    {'reference':'fuse-overlayfs-1.4.0-3.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-1.4'},
    {'reference':'fuse-overlayfs-1.4.0-3.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-1.4'},
    {'reference':'fuse-overlayfs-debuginfo-0.7.8-1.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debuginfo-0'},
    {'reference':'fuse-overlayfs-debuginfo-0.7.8-1.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debuginfo-0'},
    {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debuginfo-1.4'},
    {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debuginfo-1.4'},
    {'reference':'fuse-overlayfs-debuginfo-1.4.0-3.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debuginfo-1.4'},
    {'reference':'fuse-overlayfs-debuginfo-1.4.0-3.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debuginfo-1.4'},
    {'reference':'fuse-overlayfs-debugsource-0.7.8-1.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debugsource-0'},
    {'reference':'fuse-overlayfs-debugsource-0.7.8-1.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debugsource-0'},
    {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debugsource-1.4'},
    {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debugsource-1.4'},
    {'reference':'fuse-overlayfs-debugsource-1.4.0-3.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debugsource-1.4'},
    {'reference':'fuse-overlayfs-debugsource-1.4.0-3.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'fuse-overlayfs-debugsource-1.4'},
    {'reference':'libslirp-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.0-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.0-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.0-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.0-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-1.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-1.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-2.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-2.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-1'},
    {'reference':'podman-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-1'},
    {'reference':'podman-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-3.0'},
    {'reference':'podman-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-3.0'},
    {'reference':'podman-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-3.0'},
    {'reference':'podman-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-3.0'},
    {'reference':'podman-catatonit-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-debuginfo-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-debuginfo-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-debuginfo-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-debuginfo-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-debuginfo-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debuginfo-1'},
    {'reference':'podman-debuginfo-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debuginfo-1'},
    {'reference':'podman-debuginfo-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debuginfo-3.0'},
    {'reference':'podman-debuginfo-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debuginfo-3.0'},
    {'reference':'podman-debuginfo-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debuginfo-3.0'},
    {'reference':'podman-debuginfo-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debuginfo-3.0'},
    {'reference':'podman-debugsource-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debugsource-1'},
    {'reference':'podman-debugsource-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debugsource-1'},
    {'reference':'podman-debugsource-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debugsource-3.0'},
    {'reference':'podman-debugsource-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debugsource-3.0'},
    {'reference':'podman-debugsource-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debugsource-3.0'},
    {'reference':'podman-debugsource-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-debugsource-3.0'},
    {'reference':'podman-docker-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-docker-1'},
    {'reference':'podman-docker-3.0.1-6.module+el8.4.0+558+7340b765', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-docker-3.0'},
    {'reference':'podman-docker-3.0.1-7.module+el8.4.0+556+40122d08', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-docker-3.0'},
    {'reference':'podman-plugins-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-debuginfo-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-debuginfo-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-debuginfo-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-debuginfo-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-remote-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-1'},
    {'reference':'podman-remote-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-1'},
    {'reference':'podman-remote-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-3.0'},
    {'reference':'podman-remote-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-3.0'},
    {'reference':'podman-remote-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-3.0'},
    {'reference':'podman-remote-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-3.0'},
    {'reference':'podman-remote-debuginfo-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-debuginfo-1'},
    {'reference':'podman-remote-debuginfo-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-debuginfo-1'},
    {'reference':'podman-remote-debuginfo-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-debuginfo-3.0'},
    {'reference':'podman-remote-debuginfo-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-debuginfo-3.0'},
    {'reference':'podman-remote-debuginfo-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-debuginfo-3.0'},
    {'reference':'podman-remote-debuginfo-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-remote-debuginfo-3.0'},
    {'reference':'podman-tests-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-tests-1'},
    {'reference':'podman-tests-1.6.4-26.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-tests-1'},
    {'reference':'podman-tests-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-tests-3.0'},
    {'reference':'podman-tests-3.0.1-6.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-tests-3.0'},
    {'reference':'podman-tests-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-tests-3.0'},
    {'reference':'podman-tests-3.0.1-7.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'podman-tests-3.0'},
    {'reference':'python-podman-api-1.2.0-0.2.gitd0a45fe.module+el8.4.0+559+c02fa3b2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3-criu-3.12'},
    {'reference':'python3-criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3-criu-3.12'},
    {'reference':'python3-criu-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3-criu-3.15'},
    {'reference':'python3-criu-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3-criu-3.15'},
    {'reference':'runc-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.0-71.rc92.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.0-71.rc92.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.0-73.rc93.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.0-73.rc93.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.0-71.rc92.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.0-71.rc92.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.0-73.rc93.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.0-73.rc93.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.0-71.rc92.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.0-71.rc92.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.0-73.rc93.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.0-73.rc93.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'skopeo-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-0'},
    {'reference':'skopeo-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-0'},
    {'reference':'skopeo-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-1.2'},
    {'reference':'skopeo-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-1.2'},
    {'reference':'skopeo-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-1.2'},
    {'reference':'skopeo-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-1.2'},
    {'reference':'skopeo-debuginfo-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debuginfo-0'},
    {'reference':'skopeo-debuginfo-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debuginfo-0'},
    {'reference':'skopeo-debuginfo-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debuginfo-1.2'},
    {'reference':'skopeo-debuginfo-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debuginfo-1.2'},
    {'reference':'skopeo-debuginfo-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debuginfo-1.2'},
    {'reference':'skopeo-debuginfo-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debuginfo-1.2'},
    {'reference':'skopeo-debugsource-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debugsource-0'},
    {'reference':'skopeo-debugsource-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debugsource-0'},
    {'reference':'skopeo-debugsource-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debugsource-1.2'},
    {'reference':'skopeo-debugsource-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debugsource-1.2'},
    {'reference':'skopeo-debugsource-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debugsource-1.2'},
    {'reference':'skopeo-debugsource-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-debugsource-1.2'},
    {'reference':'skopeo-tests-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-tests-0'},
    {'reference':'skopeo-tests-0.1.41-4.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-tests-0'},
    {'reference':'skopeo-tests-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-tests-1.2'},
    {'reference':'skopeo-tests-1.2.2-10.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-tests-1.2'},
    {'reference':'skopeo-tests-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-tests-1.2'},
    {'reference':'skopeo-tests-1.2.2-7.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'skopeo-tests-1.2'},
    {'reference':'slirp4netns-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-0'},
    {'reference':'slirp4netns-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-0'},
    {'reference':'slirp4netns-1.1.8-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-1'},
    {'reference':'slirp4netns-1.1.8-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-1'},
    {'reference':'slirp4netns-debuginfo-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-debuginfo-0'},
    {'reference':'slirp4netns-debuginfo-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-debuginfo-0'},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-debuginfo-1'},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-debuginfo-1'},
    {'reference':'slirp4netns-debugsource-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-debugsource-0'},
    {'reference':'slirp4netns-debugsource-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-debugsource-0'},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-debugsource-1'},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'slirp4netns-debugsource-1'},
    {'reference':'toolbox-0.0.7-1.module+el8.4.0+559+c02fa3b2', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'toolbox-0.0'},
    {'reference':'toolbox-0.0.8-1.module+el8.4.0+556+40122d08', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'toolbox-0.0'},
    {'reference':'udica-0.2.1-2.module+el8.4.0+559+c02fa3b2', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'udica-0.2'},
    {'reference':'udica-0.2.4-1.module+el8.4.0+556+40122d08', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'udica-0.2'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-debuginfo / buildah-debugsource / buildah-tests / etc');
}
