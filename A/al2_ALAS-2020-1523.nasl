##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1523.
##

include('compat.inc');

if (description)
{
  script_id(141959);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_cve_id(
    "CVE-2019-9278",
    "CVE-2020-0093",
    "CVE-2020-0182",
    "CVE-2020-12767",
    "CVE-2020-13113",
    "CVE-2020-13114"
  );
  script_xref(name:"ALAS", value:"2020-1523");

  script_name(english:"Amazon Linux 2 : libexif (ALAS-2020-1523)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1523 advisory.

  - In libexif, there is a possible out of bounds write due to an integer overflow. This could lead to remote
    escalation of privilege in the media content provider with no additional execution privileges needed. User
    interaction is needed for exploitation. Product: AndroidVersions: Android-10Android ID: A-112537774
    (CVE-2019-9278)

  - In exif_data_save_data_entry of exif-data.c, there is a possible out of bounds read due to a missing
    bounds check. This could lead to local information disclosure with no additional execution privileges
    needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1
    Android-9 Android-10Android ID: A-148705132 (CVE-2020-0093)

  - In exif_entry_get_value of exif-entry.c, there is a possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure with no additional execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID:
    A-147140917 (CVE-2020-0182)

  - exif_entry_get_value in exif-entry.c in libexif 0.6.21 has a divide-by-zero error. (CVE-2020-12767)

  - An issue was discovered in libexif before 0.6.22. Use of uninitialized memory in EXIF Makernote handling
    could lead to crashes and potential use-after-free conditions. (CVE-2020-13113)

  - An issue was discovered in libexif before 0.6.22. An unrestricted size in handling Canon EXIF MakerNote
    data could lead to consumption of large amounts of compute time for decoding EXIF data. (CVE-2020-13114)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1523.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9278");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0093");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0182");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12767");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-13113");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-13114");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libexif' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9278");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libexif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libexif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libexif-doc");
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
    {'reference':'libexif-0.6.22-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libexif-0.6.22-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libexif-0.6.22-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libexif-debuginfo-0.6.22-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libexif-debuginfo-0.6.22-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libexif-debuginfo-0.6.22-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libexif-devel-0.6.22-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libexif-devel-0.6.22-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libexif-devel-0.6.22-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libexif-doc-0.6.22-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libexif-doc-0.6.22-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libexif-doc-0.6.22-1.amzn2', 'cpu':'x86_64', 'release':'AL2'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libexif / libexif-debuginfo / libexif-devel / etc");
}