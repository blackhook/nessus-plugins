#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1488.
#

include('compat.inc');

if (description)
{
  script_id(140209);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");

  script_cve_id("CVE-2020-14386");
  script_xref(name:"ALAS", value:"2020-1488");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2020-1488)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the ALAS2-2020-1488 advisory.

  - An issue has been reported in the Linux kernel's handling of raw sockets. This issue can be used locally
    to cause denial of service or local privilege escalation from unprivileged processes or from containers
    with the CAP_NET_RAW capability enabled. (CVE-2020-14386)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1488.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14386");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.193-149.317");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  cve_list = make_list("CVE-2020-14386");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2020-1488");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
pkgs = [
    {'reference':'kernel-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-aarch64-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.193-149.317.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-livepatch-4.14.193-149.317-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.193-149.317.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.193-149.317.amzn2', 'cpu':'x86_64', 'release':'AL2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}
