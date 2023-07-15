#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-7954.
##

include('compat.inc');

if (description)
{
  script_id(168070);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/22");

  script_cve_id(
    "CVE-2020-28851",
    "CVE-2020-28852",
    "CVE-2021-4024",
    "CVE-2021-20199",
    "CVE-2021-20291",
    "CVE-2021-33197",
    "CVE-2021-34558",
    "CVE-2022-27191"
  );
  script_xref(name:"IAVB", value:"2021-B-0047-S");

  script_name(english:"Oracle Linux 9 : podman (ELSA-2022-7954)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-7954 advisory.

  - In x/text in Go 1.15.4, an index out of range panic occurs in language.ParseAcceptLanguage while parsing
    the -u- extension. (x/text/language is supposed to be able to parse an HTTP Accept-Language header.)
    (CVE-2020-28851)

  - A deadlock vulnerability was found in 'github.com/containers/storage' in versions before 1.28.1. When a
    container image is processed, each layer is unpacked using `tar`. If one of those layers is not a valid
    `tar` archive this causes an error leading to an unexpected situation where the code indefinitely waits
    for the tar unpacked stream, which never finishes. An attacker could use this vulnerability to craft a
    malicious image, which when downloaded and stored by an application using containers/storage, would then
    cause a deadlock leading to a Denial of Service (DoS). (CVE-2021-20291)

  - Rootless containers run with Podman, receive all traffic with a source IP address of 127.0.0.1 (including
    from remote hosts). This impacts containerized applications that trust localhost (127.0.01) connections by
    default and do not require authentication. This issue affects Podman 1.8.0 onwards. (CVE-2021-20199)

  - In x/text in Go before v0.3.5, a slice bounds out of range panic occurs in language.ParseAcceptLanguage
    while processing a BCP 47 tag. (x/text/language is supposed to be able to parse an HTTP Accept-Language
    header.) (CVE-2020-28852)

  - A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual
    machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is
    accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an
    attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making
    private services on the VM accessible to the network. This issue could be also used to interrupt the
    host's services by forwarding all ports to the VM. (CVE-2021-4024)

  - In Go before 1.15.13 and 1.16.x before 1.16.5, some configurations of ReverseProxy (from
    net/http/httputil) result in a situation where an attacker is able to drop arbitrary headers.
    (CVE-2021-33197)

  - The crypto/tls package of Go through 1.16.5 does not properly assert that the type of public key in an
    X.509 certificate matches the expected type when doing a RSA based key exchange, allowing a malicious TLS
    server to cause a TLS client to panic. (CVE-2021-34558)

  - The golang.org/x/crypto/ssh package before 0.0.0-20220314234659-1baeb1ce4c0b for Go allows an attacker to
    crash a server in certain circumstances involving AddHostKey. (CVE-2022-27191)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-7954.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4024");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-tests");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'podman-4.2.0-3.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-4.2.0-3.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-catatonit-4.2.0-3.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-catatonit-4.2.0-3.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-docker-4.2.0-3.0.1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-gvproxy-4.2.0-3.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-gvproxy-4.2.0-3.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-plugins-4.2.0-3.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-plugins-4.2.0-3.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-remote-4.2.0-3.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-remote-4.2.0-3.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-tests-4.2.0-3.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'podman-tests-4.2.0-3.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'podman / podman-catatonit / podman-docker / etc');
}
