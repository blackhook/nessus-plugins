#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:23018-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158634);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/05");

  script_cve_id(
    "CVE-2020-14370",
    "CVE-2020-15157",
    "CVE-2021-3602",
    "CVE-2021-4024",
    "CVE-2021-20199",
    "CVE-2021-20291",
    "CVE-2021-41190"
  );

  script_name(english:"openSUSE 15 Security Update : conmon, libcontainers-common, libseccomp, podman (openSUSE-SU-2022:23018-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:23018-1 advisory.

  - An information disclosure vulnerability was found in containers/podman in versions before 2.0.5. When
    using the deprecated Varlink API or the Docker-compatible REST API, if multiple containers are created in
    a short duration, the environment variables from the first container will get leaked into subsequent
    containers. An attacker who has control over the subsequent containers could use this flaw to gain access
    to sensitive information stored in such variables. (CVE-2020-14370)

  - In containerd (an industry-standard container runtime) before version 1.2.14 there is a credential leaking
    vulnerability. If a container image manifest in the OCI Image format or Docker Image V2 Schema 2 format
    includes a URL for the location of a specific image layer (otherwise known as a foreign layer), the
    default containerd resolver will follow that URL to attempt to download it. In v1.2.x but not 1.3.0 or
    later, the default containerd resolver will provide its authentication credentials if the server where the
    URL is located presents an HTTP 401 status code along with registry-specific HTTP headers. If an attacker
    publishes a public image with a manifest that directs one of the layers to be fetched from a web server
    they control and they trick a user or system into pulling the image, they can obtain the credentials used
    for pulling that image. In some cases, this may be the user's username and password for the registry. In
    other cases, this may be the credentials attached to the cloud virtual instance which can grant access to
    other cloud resources in the account. The default containerd resolver is used by the cri-containerd plugin
    (which can be used by Kubernetes), the ctr development tool, and other client programs that have
    explicitly linked against it. This vulnerability has been fixed in containerd 1.2.14. containerd 1.3 and
    later are not affected. If you are using containerd 1.3 or later, you are not affected. If you are using
    cri-containerd in the 1.2 series or prior, you should ensure you only pull images from trusted sources.
    Other container runtimes built on top of containerd but not using the default resolver (such as Docker)
    are not affected. (CVE-2020-15157)

  - Rootless containers run with Podman, receive all traffic with a source IP address of 127.0.0.1 (including
    from remote hosts). This impacts containerized applications that trust localhost (127.0.01) connections by
    default and do not require authentication. This issue affects Podman 1.8.0 onwards. (CVE-2021-20199)

  - A deadlock vulnerability was found in 'github.com/containers/storage' in versions before 1.28.1. When a
    container image is processed, each layer is unpacked using `tar`. If one of those layers is not a valid
    `tar` archive this causes an error leading to an unexpected situation where the code indefinitely waits
    for the tar unpacked stream, which never finishes. An attacker could use this vulnerability to craft a
    malicious image, which when downloaded and stored by an application using containers/storage, would then
    cause a deadlock leading to a Denial of Service (DoS). (CVE-2021-20291)

  - An information disclosure flaw was found in Buildah, when building containers using chroot isolation.
    Running processes in container builds (e.g. Dockerfile RUN commands) can access environment variables from
    parent and grandparent processes. When run in a container in a CI/CD environment, environment variables
    may include sensitive information that was shared with the container in order to be used only by Buildah
    itself (e.g. container registry credentials). (CVE-2021-3602)

  - A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual
    machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is
    accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an
    attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making
    private services on the VM accessible to the network. This issue could be also used to interrupt the
    host's services by forwarding all ports to the VM. (CVE-2021-4024)

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193273");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5BA2TLW7O5ZURGQUAQUH4HD5SQYNDDZ6/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8e88443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14370");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41190");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4024");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcontainers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podman-cni-config");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'conmon-2.0.30-150300.8.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcontainers-common-20210626-150300.8.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libseccomp-devel-2.5.3-150300.10.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libseccomp-tools-2.5.3-150300.10.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libseccomp2-2.5.3-150300.10.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libseccomp2-32bit-2.5.3-150300.10.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-3.4.4-150300.9.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-cni-config-3.4.4-150300.9.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'conmon / libcontainers-common / libseccomp-devel / libseccomp-tools / etc');
}
