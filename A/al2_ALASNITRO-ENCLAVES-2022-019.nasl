##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASNITRO-ENCLAVES-2022-019.
##

include('compat.inc');

if (description)
{
  script_id(162010);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2022-24769");

  script_name(english:"Amazon Linux 2 : containerd, docker (ALASNITRO-ENCLAVES-2022-019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of containerd installed on the remote host is prior to 1.4.13-2. The version of docker installed on the
remote host is prior to 20.10.13-2. It is, therefore, affected by a vulnerability as referenced in the ALAS2NITRO-
ENCLAVES-2022-019 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASNITRO-ENCLAVES-2022-019.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24769.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update containerd' to update your system.
 Run 'yum update docker' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24769");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-stress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'containerd-1.4.13-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'},
    {'reference':'containerd-1.4.13-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'},
    {'reference':'containerd-debuginfo-1.4.13-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'},
    {'reference':'containerd-debuginfo-1.4.13-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'},
    {'reference':'containerd-stress-1.4.13-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'},
    {'reference':'containerd-stress-1.4.13-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'},
    {'reference':'docker-20.10.13-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'},
    {'reference':'docker-20.10.13-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'},
    {'reference':'docker-debuginfo-20.10.13-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'},
    {'reference':'docker-debuginfo-20.10.13-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nitro-enclaves'}
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
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-debuginfo / containerd-stress / etc");
}