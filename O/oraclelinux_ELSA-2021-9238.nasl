#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9238.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149822);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Linux 6 : perl (ELSA-2021-9238)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-9238 advisory.

  - Perl before 5.30.3 on 32-bit platforms allows a heap-based buffer overflow because nested regular
    expression quantifiers have an integer overflow. (CVE-2020-10543)

  - Perl before 5.30.3 has an integer overflow related to mishandling of a PL_regkind[OP(n)] == NOTHING
    situation. A crafted regular expression could lead to malformed bytecode with a possibility of instruction
    injection. (CVE-2020-10878)

  - regcomp.c in Perl before 5.30.3 allows a buffer overflow via a crafted regular expression because of
    recursive S_study_chunk calls. (CVE-2020-12723)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9238.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Archive-Extract");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Archive-Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPANPLUS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Compress-Raw-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Compress-Raw-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Compress-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Digest-SHA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-MakeMaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-ParseXS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Fetch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Compress-Base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Compress-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Compress-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IPC-Cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Log-Message");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Log-Message-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Load-Conditional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Pluggable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Params-Check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Parse-CPAN-Meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Term-UI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Test-Harness");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Test-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Time-HiRes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-version");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'perl-5.10.1-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-5.10.1-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Archive-Extract-0.38-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Archive-Extract-0.38-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Archive-Tar-1.58-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Archive-Tar-1.58-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-CGI-3.51-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-CGI-3.51-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Compress-Raw-Bzip2-2.021-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Compress-Raw-Bzip2-2.021-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Compress-Raw-Zlib-2.021-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Compress-Raw-Zlib-2.021-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Compress-Zlib-2.021-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Compress-Zlib-2.021-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-core-5.10.1-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-core-5.10.1-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-CPAN-1.9402-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-CPAN-1.9402-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-CPANPLUS-0.88-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-CPANPLUS-0.88-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-devel-5.10.1-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-devel-5.10.1-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Digest-SHA-5.47-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Digest-SHA-5.47-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-ExtUtils-CBuilder-0.27-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-ExtUtils-CBuilder-0.27-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-ExtUtils-Embed-1.28-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-Embed-1.28-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-MakeMaker-6.55-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-MakeMaker-6.55-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-ParseXS-2.2003.0-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-ExtUtils-ParseXS-2.2003.0-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-File-Fetch-0.26-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-File-Fetch-0.26-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-Compress-Base-2.021-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-Compress-Base-2.021-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-Compress-Bzip2-2.021-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-Compress-Bzip2-2.021-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-Compress-Zlib-2.021-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-Compress-Zlib-2.021-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-Zlib-1.09-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-IO-Zlib-1.09-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-IPC-Cmd-0.56-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-IPC-Cmd-0.56-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-libs-5.10.1-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-5.10.1-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Locale-Maketext-Simple-0.18-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Locale-Maketext-Simple-0.18-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Log-Message-0.02-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Log-Message-0.02-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Log-Message-Simple-0.04-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Log-Message-Simple-0.04-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Module-Build-0.3500-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Module-Build-0.3500-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Module-CoreList-2.18-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Module-CoreList-2.18-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Module-Load-0.16-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Module-Load-0.16-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Module-Load-Conditional-0.30-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Module-Load-Conditional-0.30-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Module-Loaded-0.02-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Module-Loaded-0.02-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Module-Pluggable-3.90-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Module-Pluggable-3.90-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Object-Accessor-0.34-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Object-Accessor-0.34-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Package-Constants-0.02-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Package-Constants-0.02-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Params-Check-0.26-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Params-Check-0.26-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-parent-0.221-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-parent-0.221-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Parse-CPAN-Meta-1.40-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Parse-CPAN-Meta-1.40-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Pod-Escapes-1.04-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Pod-Escapes-1.04-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Pod-Simple-3.13-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Pod-Simple-3.13-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-suidperl-5.10.1-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-suidperl-5.10.1-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Term-UI-0.20-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Term-UI-0.20-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Test-Harness-3.17-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Test-Harness-3.17-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Test-Simple-0.92-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Test-Simple-0.92-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-HiRes-1.9721-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Time-HiRes-1.9721-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Time-Piece-1.15-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-1.15-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-version-0.77-144.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
    {'reference':'perl-version-0.77-144.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'perl / perl-Archive-Extract / perl-Archive-Tar / etc');
}
