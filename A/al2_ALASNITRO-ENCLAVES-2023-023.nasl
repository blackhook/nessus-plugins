#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASNITRO-ENCLAVES-2023-023.
##

include('compat.inc');

if (description)
{
  script_id(173937);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2022-23471", "CVE-2023-25153", "CVE-2023-25173");

  script_name(english:"Amazon Linux 2 : containerd (ALASNITRO-ENCLAVES-2023-023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of containerd installed on the remote host is prior to 1.6.19-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2NITRO-ENCLAVES-2023-023 advisory.

  - containerd is an open source container runtime. A bug was found in containerd's CRI implementation where a
    user can exhaust memory on the host. In the CRI stream server, a goroutine is launched to handle terminal
    resize events if a TTY is requested. If the user's process fails to launch due to, for example, a faulty
    command, the goroutine will be stuck waiting to send without a receiver, resulting in a memory leak.
    Kubernetes and crictl can both be configured to use containerd's CRI implementation and the stream server
    is used for handling container IO. This bug has been fixed in containerd 1.6.12 and 1.5.16. Users should
    update to these versions to resolve the issue. Users unable to upgrade should ensure that only trusted
    images and commands are used and that only trusted users have permissions to execute commands in running
    containers. (CVE-2022-23471)

  - containerd is an open source container runtime. Before versions 1.6.18 and 1.5.18, when importing an OCI
    image, there was no limit on the number of bytes read for certain files. A maliciously crafted image with
    a large file where a limit was not applied could cause a denial of service. This bug has been fixed in
    containerd 1.6.18 and 1.5.18. Users should update to these versions to resolve the issue. As a workaround,
    ensure that only trusted images are used and that only trusted users have permissions to import images.
    (CVE-2023-25153)

  - containerd is an open source container runtime. A bug was found in containerd prior to versions 1.6.18 and
    1.5.18 where supplementary groups are not set up properly inside a container. If an attacker has direct
    access to a container and manipulates their supplementary group access, they may be able to use
    supplementary group access to bypass primary group restrictions in some cases, potentially gaining access
    to sensitive information or gaining the ability to execute code in that container. Downstream applications
    that use the containerd client library may be affected as well. This bug has been fixed in containerd
    v1.6.18 and v.1.5.18. Users should update to these versions and recreate containers to resolve this issue.
    Users who rely on a downstream application that uses containerd's client library should check that
    application for a separate advisory and instructions. As a workaround, ensure that the `USER $USERNAME`
    Dockerfile instruction is not used. Instead, set the container entrypoint to a value similar to
    `ENTRYPOINT [su, -, user]` to allow `su` to properly set up supplementary groups. (CVE-2023-25173)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASNITRO-ENCLAVES-2023-023.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-23471.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-25153.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-25173.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update containerd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25173");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-stress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'containerd-1.6.19-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves-.0.0.0'},
    {'reference':'containerd-1.6.19-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves-.0.0.0'},
    {'reference':'containerd-debuginfo-1.6.19-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves-.0.0.0'},
    {'reference':'containerd-debuginfo-1.6.19-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves-.0.0.0'},
    {'reference':'containerd-stress-1.6.19-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves-.0.0.0'},
    {'reference':'containerd-stress-1.6.19-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves-.0.0.0'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-debuginfo / containerd-stress");
}