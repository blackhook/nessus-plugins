##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1484.
##

include('compat.inc');

if (description)
{
  script_id(146819);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_cve_id("CVE-2021-3177");
  script_xref(name:"ALAS", value:"2021-1484");

  script_name(english:"Amazon Linux AMI : python27, python36, python38 (ALAS-2021-1484)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of python27 installed on the remote host is prior to 2.7.18-2.141. The version of python36 installed on the
remote host is prior to 3.6.12-1.20. The version of python38 installed on the remote host is prior to 3.8.5-1.5. It is,
therefore, affected by a vulnerability as referenced in the ALAS-2021-1484 advisory.

  - Python 3.x through 3.9.1 has a buffer overflow in PyCArg_repr in _ctypes/callproc.c, which may lead to
    remote code execution in certain Python applications that accept floating-point numbers as untrusted
    input, as demonstrated by a 1e300 argument to c_double.from_param. This occurs because sprintf is used
    unsafely. (CVE-2021-3177)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1484.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3177");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python27' to update your system.
 Run 'yum update python36' to update your system.
 Run 'yum update python38' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'python27-2.7.18-2.141.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-2.7.18-2.141.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-debuginfo-2.7.18-2.141.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-debuginfo-2.7.18-2.141.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-devel-2.7.18-2.141.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-devel-2.7.18-2.141.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-libs-2.7.18-2.141.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-libs-2.7.18-2.141.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-test-2.7.18-2.141.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-test-2.7.18-2.141.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python27-tools-2.7.18-2.141.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python27-tools-2.7.18-2.141.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python36-3.6.12-1.20.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python36-3.6.12-1.20.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python36-debug-3.6.12-1.20.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python36-debug-3.6.12-1.20.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python36-debuginfo-3.6.12-1.20.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python36-debuginfo-3.6.12-1.20.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python36-devel-3.6.12-1.20.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python36-devel-3.6.12-1.20.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python36-libs-3.6.12-1.20.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python36-libs-3.6.12-1.20.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python36-test-3.6.12-1.20.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python36-test-3.6.12-1.20.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python36-tools-3.6.12-1.20.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python36-tools-3.6.12-1.20.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python38-3.8.5-1.5.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python38-3.8.5-1.5.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python38-debug-3.8.5-1.5.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python38-debug-3.8.5-1.5.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python38-debuginfo-3.8.5-1.5.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python38-debuginfo-3.8.5-1.5.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python38-devel-3.8.5-1.5.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python38-devel-3.8.5-1.5.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python38-libs-3.8.5-1.5.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python38-libs-3.8.5-1.5.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python38-test-3.8.5-1.5.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python38-test-3.8.5-1.5.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'python38-tools-3.8.5-1.5.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'python38-tools-3.8.5-1.5.amzn1', 'cpu':'x86_64', 'release':'ALA'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python27 / python27-debuginfo / python27-devel / etc");
}