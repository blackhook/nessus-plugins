#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-218.
##

include('compat.inc');

if (description)
{
  script_id(177690);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/28");

  script_cve_id("CVE-2023-31486");

  script_name(english:"Amazon Linux 2023 : perl, perl-Attribute-Handlers, perl-AutoLoader (ALAS2023-2023-218)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2023-2023-218 advisory.

  - HTTP::Tiny before 0.083, a Perl core module since 5.13.9 and available standalone on CPAN, has an insecure
    default TLS configuration where users must opt in to verify certificates. (CVE-2023-31486)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-218.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31486.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update perl --releasever 2023.1.20230628' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31486");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Attribute-Handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-AutoLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-AutoSplit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-B");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-B-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Benchmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Class-Struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Config-Extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-DBM_Filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Devel-Peek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Devel-Peek-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Devel-SelfStubber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-DirHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Dumpvalue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-DynaLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-English");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Errno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Constant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Miniperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Fcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Fcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-File-Basename");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-File-Compare");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-File-Copy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-File-DosGlob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-File-DosGlob-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-File-Find");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-File-stat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-FileCache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-FileHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-FindBin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-GDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-GDBM_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Getopt-Std");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Hash-Util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Hash-Util-FieldHash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Hash-Util-FieldHash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Hash-Util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-I18N-Collate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-I18N-LangTags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-I18N-Langinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-I18N-Langinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IPC-Open3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Math-Complex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-NDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-NDBM_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-NEXT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ODBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ODBM_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Opcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Opcode-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-POSIX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-POSIX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Pod-Functions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Pod-Html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Search-Dict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-SelectSaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-SelfLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Sys-Hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Sys-Hostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Term-Complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Term-ReadLine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Text-Abbrev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Thread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Thread-Semaphore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Tie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Tie-File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Tie-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Time-Piece-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Unicode-UCD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-User-pwent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-autouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-blib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-deprecate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-diagnostics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-encoding-warnings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-fields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-filetest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-if");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-interpreter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-interpreter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-less");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-libnetcfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-meta-notation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-mro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-mro-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-overload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-overloading");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-sigtrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-sort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-subs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-vars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-vmsish");
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
    {'reference':'perl-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Attribute-Handlers-1.01-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-AutoLoader-5.74-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-AutoSplit-5.74-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-autouse-1.11-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-B-1.80-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-B-1.80-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-B-1.80-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-B-debuginfo-1.80-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-B-debuginfo-1.80-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-B-debuginfo-1.80-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-base-2.27-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Benchmark-1.23-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-blib-1.07-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Class-Struct-0.66-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Config-Extensions-0.03-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-DBM_Filter-0.06-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debugger-1.56-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debuginfo-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debuginfo-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debuginfo-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debugsource-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debugsource-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debugsource-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-deprecate-0.04-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-devel-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-devel-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-devel-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-Peek-1.28-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-Peek-1.28-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-Peek-1.28-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-Peek-debuginfo-1.28-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-Peek-debuginfo-1.28-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-Peek-debuginfo-1.28-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-SelfStubber-1.06-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-diagnostics-1.37-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-DirHandle-1.05-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-doc-5.32.1-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Dumpvalue-2.27-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-DynaLoader-1.47-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-DynaLoader-1.47-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-DynaLoader-1.47-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-encoding-warnings-0.13-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-English-1.11-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Errno-1.30-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Errno-1.30-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Errno-1.30-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-Constant-0.25-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-Embed-1.35-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-Miniperl-1.09-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Fcntl-1.13-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Fcntl-1.13-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Fcntl-1.13-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Fcntl-debuginfo-1.13-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Fcntl-debuginfo-1.13-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Fcntl-debuginfo-1.13-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-fields-2.27-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-Basename-2.85-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-Compare-1.100.600-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-Copy-2.34-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-DosGlob-1.12-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-DosGlob-1.12-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-DosGlob-1.12-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-DosGlob-debuginfo-1.12-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-DosGlob-debuginfo-1.12-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-DosGlob-debuginfo-1.12-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-Find-1.37-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-stat-1.09-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-FileCache-1.10-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-FileHandle-2.03-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-filetest-1.03-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-FindBin-1.51-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-GDBM_File-1.18-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-GDBM_File-1.18-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-GDBM_File-1.18-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-GDBM_File-debuginfo-1.18-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-GDBM_File-debuginfo-1.18-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-GDBM_File-debuginfo-1.18-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Getopt-Std-1.12-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-0.23-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-0.23-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-0.23-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-debuginfo-0.23-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-debuginfo-0.23-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-debuginfo-0.23-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-FieldHash-1.20-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-FieldHash-1.20-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-FieldHash-1.20-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-FieldHash-debuginfo-1.20-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-FieldHash-debuginfo-1.20-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Hash-Util-FieldHash-debuginfo-1.20-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-I18N-Collate-1.02-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-I18N-Langinfo-0.19-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-I18N-Langinfo-0.19-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-I18N-Langinfo-0.19-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-I18N-Langinfo-debuginfo-0.19-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-I18N-Langinfo-debuginfo-0.19-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-I18N-Langinfo-debuginfo-0.19-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-I18N-LangTags-0.44-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-if-0.60.800-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-interpreter-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-interpreter-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-interpreter-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-interpreter-debuginfo-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-interpreter-debuginfo-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-interpreter-debuginfo-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-1.43-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-1.43-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-1.43-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-debuginfo-1.43-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-debuginfo-1.43-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-debuginfo-1.43-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IPC-Open3-1.21-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-less-0.03-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-lib-0.65-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-lib-0.65-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-lib-0.65-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-libnetcfg-5.32.1-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-libs-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-libs-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-libs-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-libs-debuginfo-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-libs-debuginfo-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-libs-debuginfo-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-locale-1.09-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Locale-Maketext-Simple-0.21-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-macros-5.32.1-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Math-Complex-1.59-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Memoize-1.03-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-meta-notation-5.32.1-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Module-Loaded-0.08-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-mro-1.23-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-mro-1.23-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-mro-1.23-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-mro-debuginfo-1.23-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-mro-debuginfo-1.23-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-mro-debuginfo-1.23-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-NDBM_File-1.15-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-NDBM_File-1.15-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-NDBM_File-1.15-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-NDBM_File-debuginfo-1.15-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-NDBM_File-debuginfo-1.15-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-NDBM_File-debuginfo-1.15-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Net-1.02-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-NEXT-0.67-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ODBM_File-1.16-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ODBM_File-1.16-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ODBM_File-1.16-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ODBM_File-debuginfo-1.16-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ODBM_File-debuginfo-1.16-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ODBM_File-debuginfo-1.16-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Opcode-1.48-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Opcode-1.48-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Opcode-1.48-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Opcode-debuginfo-1.48-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Opcode-debuginfo-1.48-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Opcode-debuginfo-1.48-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-open-1.12-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-overload-1.31-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-overloading-0.02-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ph-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ph-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ph-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Pod-Functions-1.13-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Pod-Html-1.25-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-POSIX-1.94-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-POSIX-1.94-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-POSIX-1.94-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-POSIX-debuginfo-1.94-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-POSIX-debuginfo-1.94-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-POSIX-debuginfo-1.94-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Safe-2.41-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Search-Dict-1.07-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-SelectSaver-1.02-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-SelfLoader-1.26-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-sigtrap-1.09-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-sort-2.04-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-subs-1.03-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Symbol-1.08-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Hostname-1.23-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Hostname-1.23-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Hostname-1.23-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Hostname-debuginfo-1.23-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Hostname-debuginfo-1.23-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Hostname-debuginfo-1.23-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Term-Complete-1.403-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Term-ReadLine-1.17-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Test-1.31-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-tests-5.32.1-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-tests-5.32.1-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-tests-5.32.1-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Text-Abbrev-1.02-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Thread-3.05-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Thread-Semaphore-2.13-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Tie-4.6-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Tie-File-1.06-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Tie-Memoize-1.1-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-1.03-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-1.3401-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-1.3401-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-1.3401-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-debuginfo-1.3401-477.amzn2023.0.5', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-debuginfo-1.3401-477.amzn2023.0.5', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-debuginfo-1.3401-477.amzn2023.0.5', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Unicode-UCD-0.75-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-User-pwent-1.03-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-utils-5.32.1-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-vars-1.05-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-vmsish-1.04-477.amzn2023.0.5', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-Attribute-Handlers / perl-AutoLoader / etc");
}