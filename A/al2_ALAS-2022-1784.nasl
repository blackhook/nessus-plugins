#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1784.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160265);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2021-42574");
  script_xref(name:"IAVA", value:"2021-A-0528");
  script_xref(name:"ALAS", value:"2022-1784");

  script_name(english:"Amazon Linux 2 : gcc10, gcc (ALAS-2022-1784)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of gcc installed on the remote host is prior to 7.3.1-14. The version of gcc10 installed on the remote host
is prior to 10.3.1-1. It is, therefore, affected by a vulnerability as referenced in the ALAS2-2022-1784 advisory.

  - An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It
    permits the visual reordering of characters via control sequences, which can be used to craft source code
    that renders different logic than the logical ordering of tokens ingested by compilers and interpreters.
    Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted
    vulnerabilities are introduced invisibly to human reviewers. (CVE-2021-42574)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1784.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-42574.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update gcc10' to update your system.
 Run 'yum update gcc' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42574");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cpp10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc10-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc10-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc10-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libasan10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libasan10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libatomic10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcilkrts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgccjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgccjit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libitm10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmpx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libquadmath10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsanitizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libstdc++10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libstdc++10-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'cpp-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp10-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp10-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp10-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-base-debuginfo-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-base-debuginfo-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-base-debuginfo-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-debuginfo-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-debuginfo-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-debuginfo-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gnat-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gnat-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gnat-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-go-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-go-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-go-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-objc++-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-objc++-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-objc++-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-objc-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-objc-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-objc-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-c++-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-c++-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-c++-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-debuginfo-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-debuginfo-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-debuginfo-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-gdb-plugin-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-gdb-plugin-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-gdb-plugin-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-plugin-devel-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-plugin-devel-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc10-plugin-devel-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan10-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan10-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan10-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan10-devel-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan10-devel-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan10-devel-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic10-devel-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic10-devel-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic10-devel-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcilkrts-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcilkrts-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgnat-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgnat-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgnat-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgo-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgo-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgo-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm10-devel-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm10-devel-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm10-devel-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmpx-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmpx-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libobjc-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libobjc-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libobjc-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath10-devel-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath10-devel-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsanitizer-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsanitizer-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsanitizer-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-7.3.1-14.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-7.3.1-14.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-7.3.1-14.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++10-devel-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++10-devel-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++10-devel-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++10-docs-10.3.1-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++10-docs-10.3.1-1.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++10-docs-10.3.1-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var allowmaj = NULL;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / cpp10 / gcc / etc");
}