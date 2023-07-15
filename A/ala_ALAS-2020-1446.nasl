##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1446.
##

include('compat.inc');

if (description)
{
  script_id(142978);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-0423",
    "CVE-2020-12351",
    "CVE-2020-12352",
    "CVE-2020-14386",
    "CVE-2020-24490",
    "CVE-2020-25211"
  );
  script_xref(name:"ALAS", value:"2020-1446");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2020-1446)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS-2020-1446 advisory.

  - In binder_release_work of binder.c, there is a possible use-after-free due to improper locking. This could
    lead to local escalation of privilege in the kernel with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-161151868References: N/A (CVE-2020-0423)

  - A flaw was found in the Linux kernel before 5.9-rc4. Memory corruption can be exploited to gain root
    privileges from unprivileged processes. The highest threat from this vulnerability is to data
    confidentiality and integrity. (CVE-2020-14386)

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1446.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0423");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12351");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12352");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14386");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24490");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25211");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14386");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  cve_list = make_list("CVE-2020-0423", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-14386", "CVE-2020-24490", "CVE-2020-25211");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2020-1446");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
pkgs = [
    {'reference':'kernel-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'kernel-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'kernel-debuginfo-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'kernel-debuginfo-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'kernel-debuginfo-common-i686-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'kernel-devel-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'kernel-devel-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'kernel-headers-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'kernel-headers-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'kernel-tools-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'kernel-tools-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'kernel-tools-debuginfo-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'kernel-tools-debuginfo-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'kernel-tools-devel-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'kernel-tools-devel-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'perf-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'perf-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'perf-debuginfo-4.14.203-116.332.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'perf-debuginfo-4.14.203-116.332.amzn1', 'cpu':'x86_64', 'release':'ALA'}
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