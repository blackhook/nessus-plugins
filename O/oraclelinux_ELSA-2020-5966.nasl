##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5966.
##

include('compat.inc');

if (description)
{
  script_id(143486);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id("CVE-2020-15257");

  script_name(english:"Oracle Linux 7 : docker-cli / docker-engine (ELSA-2020-5966)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2020-5966 advisory.

  - containerd is an industry-standard container runtime and is available as a daemon for Linux and Windows.
    In containerd before versions 1.3.9 and 1.4.3, the containerd-shim API is improperly exposed to host
    network containers. Access controls for the shim's API socket verified that the connecting process had an
    effective UID of 0, but did not otherwise restrict access to the abstract Unix domain socket. This would
    allow malicious containers running in the same network namespace as the shim, with an effective UID of 0
    but otherwise reduced privileges, to cause new processes to be run with elevated privileges. This
    vulnerability has been fixed in containerd 1.3.9 and 1.4.3. Users should update to these versions as soon
    as they are released. It should be noted that containers started with an old version of containerd-shim
    should be stopped and restarted, as running containers will continue to be vulnerable even after an
    upgrade. If you are not providing the ability for untrusted users to start containers in the same network
    namespace as the shim (typically the host network namespace, for example with docker run --net=host or
    hostNetwork: true in a Kubernetes pod) and run with an effective UID of 0, you are not vulnerable to this
    issue. If you are running containers with a vulnerable configuration, you can deny access to all abstract
    sockets with AppArmor by adding a line similar to deny unix addr=@**, to your policy. It is best practice
    to run containers with a reduced set of privileges, with a non-zero UID, and with isolated namespaces. The
    containerd maintainers strongly advise against sharing namespaces with the host. Reducing the set of
    isolation mechanisms used for a container necessarily increases that container's privilege, regardless of
    what container runtime is used for running that container. (CVE-2020-15257)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5966.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker-cli and / or docker-engine packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-engine");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'docker-cli-19.03.11.ol-7.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'docker-cli-19.03.11.ol-7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'docker-engine-19.03.11.ol-7.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'docker-engine-19.03.11.ol-7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'docker-cli / docker-engine');
}
