#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:2802.
##

include('compat.inc');

if (description)
{
  script_id(176117);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-2989",
    "CVE-2022-27664",
    "CVE-2022-28131",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30635",
    "CVE-2022-32148",
    "CVE-2022-32189",
    "CVE-2022-41717",
    "CVE-2023-0778"
  );
  script_xref(name:"ALSA", value:"2023:2802");
  script_xref(name:"IAVB", value:"2022-B-0059-S");
  script_xref(name:"IAVB", value:"2022-B-0025-S");

  script_name(english:"AlmaLinux 8 : container-tools:4.0 (ALSA-2023:2802)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:2802 advisory.

  - Acceptance of some invalid Transfer-Encoding headers in the HTTP/1 client in net/http before Go 1.17.12
    and Go 1.18.4 allows HTTP request smuggling if combined with an intermediate server that also improperly
    fails to reject the header as invalid. (CVE-2022-1705)

  - Uncontrolled recursion in the Parse functions in go/parser before Go 1.17.12 and Go 1.18.4 allow an
    attacker to cause a panic due to stack exhaustion via deeply nested types or declarations. (CVE-2022-1962)

  - In net/http in Go before 1.18.6 and 1.19.x before 1.19.1, attackers can cause a denial of service because
    an HTTP/2 connection can hang during closing if shutdown were preempted by a fatal error. (CVE-2022-27664)

  - Uncontrolled recursion in Decoder.Skip in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker
    to cause a panic due to stack exhaustion via a deeply nested XML document. (CVE-2022-28131)

  - An incorrect handling of the supplementary groups in the Podman container engine might lead to the
    sensitive information disclosure or possible data modification if an attacker has direct access to the
    affected container where supplementary groups are used to set access permissions and is able to execute a
    binary code in that container. (CVE-2022-2989)

  - Uncontrolled recursion in Glob in io/fs before Go 1.17.12 and Go 1.18.4 allows an attacker to cause a
    panic due to stack exhaustion via a path which contains a large number of path separators.
    (CVE-2022-30630)

  - Uncontrolled recursion in Reader.Read in compress/gzip before Go 1.17.12 and Go 1.18.4 allows an attacker
    to cause a panic due to stack exhaustion via an archive containing a large number of concatenated 0-length
    compressed files. (CVE-2022-30631)

  - Uncontrolled recursion in Glob in path/filepath before Go 1.17.12 and Go 1.18.4 allows an attacker to
    cause a panic due to stack exhaustion via a path containing a large number of path separators.
    (CVE-2022-30632)

  - Uncontrolled recursion in Unmarshal in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker to
    cause a panic due to stack exhaustion via unmarshalling an XML document into a Go struct which has a
    nested field that uses the 'any' field tag. (CVE-2022-30633)

  - Uncontrolled recursion in Decoder.Decode in encoding/gob before Go 1.17.12 and Go 1.18.4 allows an
    attacker to cause a panic due to stack exhaustion via a message which contains deeply nested structures.
    (CVE-2022-30635)

  - Improper exposure of client IP addresses in net/http before Go 1.17.12 and Go 1.18.4 can be triggered by
    calling httputil.ReverseProxy.ServeHTTP with a Request.Header map containing a nil value for the
    X-Forwarded-For header, which causes ReverseProxy to set the client IP as the value of the X-Forwarded-For
    header. (CVE-2022-32148)

  - A too-short encoded message can cause a panic in Float.GobDecode and Rat GobDecode in math/big in Go
    before 1.17.13 and 1.18.5, potentially allowing a denial of service. (CVE-2022-32189)

  - An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server
    connections contain a cache of HTTP header keys sent by the client. While the total number of entries in
    this cache is capped, an attacker sending very large keys can cause the server to allocate approximately
    64 MiB per open connection. (CVE-2022-41717)

  - A Time-of-check Time-of-use (TOCTOU) flaw was found in podman. This issue may allow a malicious user to
    replace a normal file in a volume with a symlink while exporting the volume, allowing for access to
    arbitrary files on the host file system. (CVE-2023-0778)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-2802.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0778");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2989");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(1325, 367, 400, 770, 842);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:criu-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libslirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libslirp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:udica");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/container-tools');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:4.0');
if ('4.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module container-tools:' + module_ver);

var appstreams = {
    'container-tools:4.0': [
      {'reference':'aardvark-dns-1.0.1-37.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'aardvark-dns-1.0.1-37.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-1.24.6-5.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'buildah-1.24.6-5.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'buildah-tests-1.24.6-5.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'buildah-tests-1.24.6-5.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'cockpit-podman-46-1.module_el8.7.0+3344+5bcd850f', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.1.4-1.module_el8.7.0+3344+5bcd850f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-2.1.4-1.module_el8.7.0+3344+5bcd850f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'container-selinux-2.199.0-1.module_el8.8.0+3468+16b86c82', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-1.1.1-2.module_el8.7.0+3344+5bcd850f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containernetworking-plugins-1.1.1-2.module_el8.7.0+3344+5bcd850f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-1-37.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containers-common-1-37.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'crit-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.6-1.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.6-1.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.9-1.module_el8.7.0+3344+5bcd850f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.9-1.module_el8.7.0+3344+5bcd850f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-1.module_el8.6.0+2877+8e437bf5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-1.module_el8.6.0+2877+8e437bf5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-1.module_el8.6.0+2877+8e437bf5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-1.module_el8.6.0+2877+8e437bf5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netavark-1.0.1-37.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'netavark-1.0.1-37.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-seccomp-bpf-hook-1.2.5-2.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.5-2.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-catatonit-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-catatonit-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-docker-4.0.2-20.module_el8.8.0+3468+16b86c82', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-gvproxy-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-gvproxy-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-plugins-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-plugins-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-remote-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-remote-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-tests-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-tests-4.0.2-20.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'python3-criu-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-3.module_el8.6.0+2877+8e437bf5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-podman-4.0.0-1.module_el8.6.0+2877+8e437bf5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.1.4-1.module_el8.7.0+3344+5bcd850f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'runc-1.1.4-1.module_el8.7.0+3344+5bcd850f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-1.6.2-6.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-1.6.2-6.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.6.2-6.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.6.2-6.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'slirp4netns-1.1.8-2.module_el8.6.0+2877+8e437bf5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-2.module_el8.6.0+2877+8e437bf5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-0.0.99.3-7.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-0.0.99.3-7.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-tests-0.0.99.3-7.module_el8.8.0+3468+16b86c82', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-tests-0.0.99.3-7.module_el8.8.0+3468+16b86c82', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.6-3.module_el8.6.0+2886+d33c3efb', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
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
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:4.0');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aardvark-dns / buildah / buildah-tests / cockpit-podman / conmon / etc');
}
