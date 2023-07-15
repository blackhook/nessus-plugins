##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1558.
##

include('compat.inc');

if (description)
{
  script_id(142738);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/11");

  script_cve_id(
    "CVE-2017-0393",
    "CVE-2019-9232",
    "CVE-2019-9433",
    "CVE-2020-0034"
  );
  script_bugtraq_id(95230);
  script_xref(name:"ALAS", value:"2020-1558");

  script_name(english:"Amazon Linux 2 : libvpx (ALAS-2020-1558)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1558 advisory.

  - A denial of service vulnerability in libvpx in Mediaserver could enable a remote attacker to use a
    specially crafted file to cause a device hang or reboot. This issue is rated as High due to the
    possibility of remote denial of service. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0,
    7.1. Android ID: A-30436808. (CVE-2017-0393)

  - In libvpx, there is a possible out of bounds read due to a missing bounds check. This could lead to remote
    information disclosure with no additional execution privileges needed. User interaction is not needed for
    exploitation. Product: AndroidVersions: Android-10Android ID: A-122675483 (CVE-2019-9232)

  - In libvpx, there is a possible information disclosure due to improper input validation. This could lead to
    remote information disclosure with no additional execution privileges needed. User interaction is needed
    for exploitation. Product: AndroidVersions: Android-10Android ID: A-80479354 (CVE-2019-9433)

  - In vp8_decode_frame of decodeframe.c, there is a possible out of bounds read due to improper input
    validation. This could lead to remote information disclosure if error correction were turned on, with no
    additional execution privileges needed. User interaction is not needed for exploitation.Product:
    AndroidVersions: Android-8.0 Android-8.1Android ID: A-62458770 (CVE-2020-0034)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1558.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-0393");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9232");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9433");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0034");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libvpx' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvpx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvpx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvpx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvpx-utils");
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

pkgs = [
    {'reference':'libvpx-1.3.0-8.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvpx-1.3.0-8.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvpx-1.3.0-8.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvpx-debuginfo-1.3.0-8.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvpx-debuginfo-1.3.0-8.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvpx-debuginfo-1.3.0-8.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvpx-devel-1.3.0-8.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvpx-devel-1.3.0-8.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvpx-devel-1.3.0-8.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libvpx-utils-1.3.0-8.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libvpx-utils-1.3.0-8.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libvpx-utils-1.3.0-8.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvpx / libvpx-debuginfo / libvpx-devel / etc");
}