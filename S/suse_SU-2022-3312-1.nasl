#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3312-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165254);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2020-14370",
    "CVE-2020-15157",
    "CVE-2021-3602",
    "CVE-2021-20199",
    "CVE-2021-20291"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3312-1");

  script_name(english:"SUSE SLES15 Security Update : libcontainers-common (SUSE-SU-2022:3312-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:3312-1 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189893");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012287.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c455bbd");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14370");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3602");
  script_set_attribute(attribute:"solution", value:
"Update the affected libcontainers-common package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20199");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15157");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcontainers-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libcontainers-common-20210626-150100.3.15.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'libcontainers-common-20210626-150100.3.15.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'libcontainers-common-20210626-150100.3.15.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'libcontainers-common-20210626-150100.3.15.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcontainers-common');
}
