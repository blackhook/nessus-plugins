#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0248. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132509);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-14503",
    "CVE-2018-1000877",
    "CVE-2018-1000878",
    "CVE-2019-1000019",
    "CVE-2019-1000020"
  );
  script_bugtraq_id(106324);

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : libarchive Multiple Vulnerabilities (NS-SA-2019-0248)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has libarchive packages installed that are
affected by multiple vulnerabilities:

  - libarchive version commit
    416694915449219d505531b1096384f3237dd6cc onwards
    (release v3.1.0 onwards) contains a CWE-415: Double Free
    vulnerability in RAR decoder -
    libarchive/archive_read_support_format_rar.c,
    parse_codes(), realloc(rar->lzss.window, new_size) with
    new_size = 0 that can result in Crash/DoS. This attack
    appear to be exploitable via the victim must open a
    specially crafted RAR archive. (CVE-2018-1000877)

  - libarchive version commit
    416694915449219d505531b1096384f3237dd6cc onwards
    (release v3.1.0 onwards) contains a CWE-416: Use After
    Free vulnerability in RAR decoder -
    libarchive/archive_read_support_format_rar.c that can
    result in Crash/DoS - it is unknown if RCE is possible.
    This attack appear to be exploitable via the victim must
    open a specially crafted RAR archive. (CVE-2018-1000878)

  - libarchive version commit
    bf9aec176c6748f0ee7a678c5f9f9555b9a757c1 onwards
    (release v3.0.2 onwards) contains a CWE-125: Out-of-
    bounds Read vulnerability in 7zip decompression,
    archive_read_support_format_7zip.c, header_bytes() that
    can result in a crash (denial of service). This attack
    appears to be exploitable via the victim opening a
    specially crafted 7zip file. (CVE-2019-1000019)

  - libarchive 3.3.2 suffers from an out-of-bounds read
    within lha_read_data_none() in
    archive_read_support_format_lha.c when extracting a
    specially crafted lha archive, related to lha_crc16.
    (CVE-2017-14503)

  - libarchive version commit
    5a98dcf8a86364b3c2c469c85b93647dfb139961 onwards
    (version v2.8.0 onwards) contains a CWE-835: Loop with
    Unreachable Exit Condition ('Infinite Loop')
    vulnerability in ISO9660 parser,
    archive_read_support_format_iso9660.c,
    read_CE()/parse_rockridge() that can result in DoS by
    infinite loop. This attack appears to be exploitable via
    the victim opening a specially crafted ISO9660 file.
    (CVE-2019-1000020)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0248");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libarchive packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "bsdcpio-3.1.2-12.el7",
    "bsdtar-3.1.2-12.el7",
    "libarchive-3.1.2-12.el7",
    "libarchive-debuginfo-3.1.2-12.el7",
    "libarchive-devel-3.1.2-12.el7"
  ],
  "CGSL MAIN 5.05": [
    "bsdcpio-3.1.2-12.el7",
    "bsdtar-3.1.2-12.el7",
    "libarchive-3.1.2-12.el7",
    "libarchive-debuginfo-3.1.2-12.el7",
    "libarchive-devel-3.1.2-12.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libarchive");
}