#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-030.
##

include('compat.inc');

if (description)
{
  script_id(173142);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2021-42574");

  script_name(english:"Amazon Linux 2023 : cpp, gcc, gcc-c++ (ALAS2023-2023-030)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2023-2023-030 advisory.

  - ** DISPUTED ** An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through
    14.0. It permits the visual reordering of characters via control sequences, which can be used to craft
    source code that renders different logic than the logical ordering of tokens ingested by compilers and
    interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such
    that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium
    offers the following alternative approach to presenting this concern. An issue is noted in the nature of
    international text that can affect applications that implement support for The Unicode Standard and the
    Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-
    right and right-to-left characters, the visual order of tokens may be different from their logical order.
    Additionally, control characters needed to fully support the requirements of bidirectional text can
    further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such
    that the ordering of tokens perceived by human reviewers does not match what will be processed by a
    compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its
    document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also
    provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode
    Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the
    BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading
    visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.
    (CVE-2021-42574)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-030.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-42574.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update gcc --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42574");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-gdb-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-gfortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-offload-nvptx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gcc-plugin-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libasan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libasan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libatomic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgccjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgccjit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgccjit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgfortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgomp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgomp-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgomp-offload-nvptx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libitm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libitm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:liblsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:liblsan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:liblsan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libquadmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libstdc++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtsan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtsan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libubsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libubsan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libubsan-static");
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
    {'reference':'cpp-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-debugsource-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-debugsource-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-debugsource-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-offload-nvptx-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-offload-nvptx-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-static-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-static-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-static-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-static-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-static-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-static-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-offload-nvptx-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-offload-nvptx-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-static-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-static-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-static-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-static-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-static-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-static-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-static-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-static-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-static-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-debuginfo-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-static-11.3.1-4.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-static-11.3.1-4.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-static-11.3.1-4.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / cpp-debuginfo / gcc / etc");
}