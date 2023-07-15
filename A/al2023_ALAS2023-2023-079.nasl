#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-079.
##

include('compat.inc');

if (description)
{
  script_id(173188);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-23648",
    "CVE-2022-24769",
    "CVE-2022-31030",
    "CVE-2022-36109"
  );

  script_name(english:"Amazon Linux 2023 : containerd, containerd-stress (ALAS2023-2023-079)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-079 advisory.

  - containerd is a container runtime available as a daemon for Linux and Windows. A bug was found in
    containerd prior to versions 1.6.1, 1.5.10, and 1.14.12 where containers launched through containerd's CRI
    implementation on Linux with a specially-crafted image configuration could gain access to read-only copies
    of arbitrary files and directories on the host. This may bypass any policy-based enforcement on container
    setup (including a Kubernetes Pod Security Policy) and expose potentially sensitive information.
    Kubernetes and crictl can both be configured to use containerd's CRI implementation. This bug has been
    fixed in containerd 1.6.1, 1.5.10, and 1.4.12. Users should update to these versions to resolve the issue.
    (CVE-2022-23648)

  - Moby is an open-source project created by Docker to enable and accelerate software containerization. A bug
    was found in Moby (Docker Engine) prior to version 20.10.14 where containers were incorrectly started with
    non-empty inheritable Linux process capabilities, creating an atypical Linux environment and enabling
    programs with inheritable file capabilities to elevate those capabilities to the permitted set during
    `execve(2)`. Normally, when executable programs have specified permitted file capabilities, otherwise
    unprivileged users and processes can execute those programs and gain the specified file capabilities up to
    the bounding set. Due to this bug, containers which included executable programs with inheritable file
    capabilities allowed otherwise unprivileged users and processes to additionally gain these inheritable
    file capabilities up to the container's bounding set. Containers which use Linux users and groups to
    perform privilege separation inside the container are most directly impacted. This bug did not affect the
    container security sandbox as the inheritable set never contained more capabilities than were included in
    the container's bounding set. This bug has been fixed in Moby (Docker Engine) 20.10.14. Running containers
    should be stopped, deleted, and recreated for the inheritable capabilities to be reset. This fix changes
    Moby (Docker Engine) behavior such that containers are started with a more typical Linux environment. As a
    workaround, the entry point of a container can be modified to use a utility like `capsh(1)` to drop
    inheritable capabilities prior to the primary process starting. (CVE-2022-24769)

  - containerd is an open source container runtime. A bug was found in the containerd's CRI implementation
    where programs inside a container can cause the containerd daemon to consume memory without bound during
    invocation of the `ExecSync` API. This can cause containerd to consume all available memory on the
    computer, denying service to other legitimate workloads. Kubernetes and crictl can both be configured to
    use containerd's CRI implementation; `ExecSync` may be used when running probes or when executing
    processes via an exec facility. This bug has been fixed in containerd 1.6.6 and 1.5.13. Users should
    update to these versions to resolve the issue. Users unable to upgrade should ensure that only trusted
    images and commands are used. (CVE-2022-31030)

  - Moby is an open-source project created by Docker to enable software containerization. A bug was found in
    Moby (Docker Engine) where supplementary groups are not set up properly. If an attacker has direct access
    to a container and manipulates their supplementary group access, they may be able to use supplementary
    group access to bypass primary group restrictions in some cases, potentially gaining access to sensitive
    information or gaining the ability to execute code in that container. This bug is fixed in Moby (Docker
    Engine) 20.10.18. Running containers should be stopped and restarted for the permissions to be fixed. For
    users unable to upgrade, this problem can be worked around by not using the `USER $USERNAME` Dockerfile
    instruction. Instead by calling `ENTRYPOINT [su, -, user]` the supplementary groups will be set up
    properly. (CVE-2022-36109)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-079.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-23648.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24769.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31030.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-36109.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update containerd --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23648");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-stress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-stress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'containerd-1.6.8-2.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-1.6.8-2.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-1.6.8-2.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-debuginfo-1.6.8-2.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-debuginfo-1.6.8-2.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-debuginfo-1.6.8-2.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-debugsource-1.6.8-2.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-debugsource-1.6.8-2.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-debugsource-1.6.8-2.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-stress-1.6.8-2.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-stress-1.6.8-2.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-stress-1.6.8-2.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-stress-debuginfo-1.6.8-2.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-stress-debuginfo-1.6.8-2.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-stress-debuginfo-1.6.8-2.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-debuginfo / containerd-debugsource / etc");
}