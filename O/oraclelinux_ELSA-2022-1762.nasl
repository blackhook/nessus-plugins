##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-1762.
##

include('compat.inc');

if (description)
{
  script_id(161275);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2022-1227",
    "CVE-2022-21698",
    "CVE-2022-27649",
    "CVE-2022-27650",
    "CVE-2022-27651"
  );

  script_name(english:"Oracle Linux 8 : container-tools:ol8 (ELSA-2022-1762)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-1762 advisory.

  - A flaw was found in Podman, where containers were started incorrectly with non-empty default permissions.
    A vulnerability was found in Moby (Docker Engine), where containers were started incorrectly with non-
    empty inheritable Linux process capabilities. This flaw allows an attacker with access to programs with
    inheritable file capabilities to elevate those capabilities to the permitted set when execve(2) runs.
    (CVE-2022-27649)

  - A flaw was found in buildah where containers were incorrectly started with non-empty default permissions.
    A bug was found in Moby (Docker Engine) where containers were incorrectly started with non-empty
    inheritable Linux process capabilities, enabling an attacker with access to programs with inheritable file
    capabilities to elevate those capabilities to the permitted set when execve(2) runs. This has the
    potential to impact confidentiality and integrity. (CVE-2022-27651)

  - A privilege escalation flaw was found in Podman. This flaw allows an attacker to publish a malicious image
    to a public registry. Once this image is downloaded by a potential victim, the vulnerability is triggered
    after a user runs the 'podman top' command. This action gives the attacker access to the host filesystem,
    leading to information disclosure or denial of service. (CVE-2022-1227)

  - A flaw was found in crun where containers were incorrectly started with non-empty default permissions. A
    vulnerability was found in Moby (Docker Engine) where containers were started incorrectly with non-empty
    inheritable Linux process capabilities. This flaw allows an attacker with access to programs with
    inheritable file capabilities to elevate those capabilities to the permitted set when execve(2) runs.
    (CVE-2022-27650)

  - client_golang is the instrumentation library for Go applications in Prometheus, and the promhttp package
    in client_golang provides tooling around HTTP servers and clients. In client_golang prior to version
    1.11.1, HTTP server is susceptible to a Denial of Service through unbounded cardinality, and potential
    memory exhaustion, when handling requests with non-standard HTTP methods. In order to be affected, an
    instrumented software must use any of `promhttp.InstrumentHandler*` middleware except `RequestsInFlight`;
    not filter any specific methods (e.g GET) before middleware; pass metric with `method` label name to our
    middleware; and not have any firewall/LB/proxy that filters away requests with unknown `method`.
    client_golang version 1.11.1 contains a patch for this issue. Several workarounds are available, including
    removing the `method` label name from counter/gauge used in the InstrumentHandler; turning off affected
    promhttp handlers; adding custom middleware before promhttp handler that will sanitize the request method
    given by Go http.Request; and using a reverse proxy or web application firewall, configured to only allow
    a limited set of methods. (CVE-2022-21698)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-1762.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

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
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
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
      {'reference':'aardvark-dns-1.0.1-27.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'aardvark-dns-1.0.1-27.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-1.24.2-4.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'buildah-1.24.2-4.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'buildah-tests-1.24.2-4.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'buildah-tests-1.24.2-4.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'cockpit-podman-43-1.module+el8.6.0+20656+53f7e955', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'conmon-2.1.0-1.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-2.1.0-1.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'container-selinux-2.179.1-1.module+el8.6.0+20656+53f7e955', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-1.0.1-2.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containernetworking-plugins-1.0.1-2.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-1-27.0.1.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containers-common-1-27.0.1.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'crit-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.4.4-1.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.4.4-1.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.8.2-1.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.8.2-1.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-1.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-1.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-1.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-1.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netavark-1.0.1-27.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'netavark-1.0.1-27.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-seccomp-bpf-hook-1.2.3-3.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.3-3.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-catatonit-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-catatonit-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-docker-4.0.2-6.module+el8.6.0+20656+53f7e955', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-gvproxy-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-gvproxy-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-plugins-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-plugins-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-remote-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-remote-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-tests-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-tests-4.0.2-6.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'python3-criu-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-3.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-podman-4.0.0-1.module+el8.6.0+20656+53f7e955', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.3-2.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'runc-1.0.3-2.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-1.6.1-2.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-1.6.1-2.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.6.1-2.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.6.1-2.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'slirp4netns-1.1.8-2.module+el8.6.0+20656+53f7e955', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-2.module+el8.6.0+20656+53f7e955', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.6-2.module+el8.6.0+20656+53f7e955', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
