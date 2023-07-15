#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:7457.
##

include('compat.inc');

if (description)
{
  script_id(171546);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id(
    "CVE-2021-36221",
    "CVE-2021-41190",
    "CVE-2022-1708",
    "CVE-2022-2990",
    "CVE-2022-27191",
    "CVE-2022-29162"
  );
  script_xref(name:"RLSA", value:"2022:7457");

  script_name(english:"Rocky Linux 8 : container-tools:rhel8 (RLSA-2022:7457)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2022:7457 advisory.

  - runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. A bug
    was found in runc prior to version 1.1.2 where `runc exec --cap` created processes with non-empty
    inheritable Linux process capabilities, creating an atypical Linux environment and enabling programs with
    inheritable file capabilities to elevate those capabilities to the permitted set during execve(2). This
    bug did not affect the container security sandbox as the inheritable set never contained more capabilities
    than were included in the container's bounding set. This bug has been fixed in runc 1.1.2. This fix
    changes `runc exec --cap` behavior such that the additional capabilities granted to the process being
    executed (as specified via `--cap` arguments) do not include inheritable capabilities. In addition, `runc
    spec` is changed to not set any inheritable capabilities in the created example OCI spec (`config.json`)
    file. (CVE-2022-29162)

  - Go before 1.15.15 and 1.16.x before 1.16.7 has a race condition that can lead to a net/http/httputil
    ReverseProxy panic upon an ErrAbortHandler abort. (CVE-2021-36221)

  - The OCI Distribution Spec project defines an API protocol to facilitate and standardize the distribution
    of content. In the OCI Distribution Specification version 1.0.0 and prior, the Content-Type header alone
    was used to determine the type of document during push and pull operations. Documents that contain both
    manifests and layers fields could be interpreted as either a manifest or an index in the absence of an
    accompanying Content-Type header. If a Content-Type header changed between two pulls of the same digest, a
    client may interpret the resulting content differently. The OCI Distribution Specification has been
    updated to require that a mediaType value present in a manifest or index match the Content-Type header
    used during the push and pull operations. Clients pulling from a registry may distrust the Content-Type
    header and reject an ambiguous document that contains both manifests and layers fields or manifests
    and config fields if they are unable to update to version 1.0.1 of the spec. (CVE-2021-41190)

  - A vulnerability was found in CRI-O that causes memory or disk space exhaustion on the node for anyone with
    access to the Kube API. The ExecSync request runs commands in a container and logs the output of the
    command. This output is then read by CRI-O after command execution, and it is read in a manner where the
    entire file corresponding to the output of the command is read in. Thus, if the output of the command is
    large it is possible to exhaust the memory or the disk space of the node when CRI-O reads the output of
    the command. The highest threat from this vulnerability is system availability. (CVE-2022-1708)

  - An incorrect handling of the supplementary groups in the Buildah container engine might lead to the
    sensitive information disclosure or possible data modification if an attacker has direct access to the
    affected container where supplementary groups are used to set access permissions and is able to execute a
    binary code in that container. (CVE-2022-2990)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:7457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1820551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1941727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1945929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1974423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1995656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1996050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2005866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2009264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2009346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2024938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2027662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2028408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2030195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2039045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2052697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2053990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2055313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2059666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2062697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2064702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2066145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2068006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2072452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2073958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2078925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2079759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2079761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2081836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2083570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2083997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2085361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2086398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2086757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2090609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2090920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2093079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2094610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2094875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2095097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2096264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2100740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2102140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2102361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2102381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2113941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2117699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2117928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2118231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2120651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2121453");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29162");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-libs-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:udica");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'cockpit-podman-53-1.module+el8.7.0+1078+e72fcd4f', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'conmon-2.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-2.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debuginfo-2.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debuginfo-2.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debugsource-2.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debugsource-2.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'container-selinux-2.189.0-1.module+el8.6.0+1054+50b00ff4', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'container-selinux-2.189.0-1.module+el8.7.0+1076+9b1c11c1', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'containernetworking-plugins-1.1.1-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-1.1.1-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-1.1.1-3.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-1.1.1-3.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-debuginfo-1.1.1-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-debuginfo-1.1.1-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-debuginfo-1.1.1-3.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-debuginfo-1.1.1-3.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-debugsource-1.1.1-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-debugsource-1.1.1-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-debugsource-1.1.1-3.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'containernetworking-plugins-debugsource-1.1.1-3.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'crit-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-1.5-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-1.5-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-1.5-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-1.5-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debuginfo-1.5-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debuginfo-1.5-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debuginfo-1.5-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debuginfo-1.5-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debugsource-1.5-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debugsource-1.5-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debugsource-1.5-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debugsource-1.5-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-1.9-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-1.9-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-1.9-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-1.9-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debuginfo-1.9-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debuginfo-1.9-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debuginfo-1.9-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debuginfo-1.9-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debugsource-1.9-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debugsource-1.9-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debugsource-1.9-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debugsource-1.9-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.6-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.6-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.6-1.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.6-1.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.6-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.6-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.6-1.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.6-1.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.6-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.6-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.6-1.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.6-1.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'runc-1.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'runc-debuginfo-1.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'runc-debuginfo-1.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'runc-debugsource-1.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'runc-debugsource-1.1.4-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'slirp4netns-1.2.0-2.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.2.0-2.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.2.0-2.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.2.0-2.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.2.0-2.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.2.0-2.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.2.0-2.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.2.0-2.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.2.0-2.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.2.0-2.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.2.0-2.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.2.0-2.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.99.3-0.6.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.99.3-0.6.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.99.3-0.6.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.99.3-0.6.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debuginfo-0.0.99.3-0.6.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debuginfo-0.0.99.3-0.6.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debuginfo-0.0.99.3-0.6.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debuginfo-0.0.99.3-0.6.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debugsource-0.0.99.3-0.6.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debugsource-0.0.99.3-0.6.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debugsource-0.0.99.3-0.6.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debugsource-0.0.99.3-0.6.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-tests-0.0.99.3-0.6.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-tests-0.0.99.3-0.6.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-tests-0.0.99.3-0.6.module+el8.7.0+1078+e72fcd4f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-tests-0.0.99.3-0.6.module+el8.7.0+1078+e72fcd4f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'udica-0.2.6-3.module+el8.6.0+971+69b94baf', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'udica-0.2.6-3.module+el8.7.0+1077+0e4f03d4', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cockpit-podman / conmon / conmon-debuginfo / conmon-debugsource / etc');
}
