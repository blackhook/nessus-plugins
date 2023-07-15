#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130670);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id(
    "CVE-2014-9496",
    "CVE-2014-9756",
    "CVE-2017-14245",
    "CVE-2017-14246",
    "CVE-2017-14634",
    "CVE-2017-16942",
    "CVE-2017-17456",
    "CVE-2017-17457",
    "CVE-2017-6892",
    "CVE-2017-7585",
    "CVE-2017-7586",
    "CVE-2017-7741",
    "CVE-2017-7742",
    "CVE-2017-8361",
    "CVE-2017-8362",
    "CVE-2017-8363",
    "CVE-2017-8365"
  );
  script_bugtraq_id(
    71796
  );

  script_name(english:"EulerOS 2.0 SP5 : libsndfile (EulerOS-SA-2019-2208)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libsndfile package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In libsndfile version 1.0.28, an error in the
    'aiff_read_chanmap()' function (aiff.c) can be
    exploited to cause an out-of-bounds read memory access
    via a specially crafted AIFF file.(CVE-2017-6892)

  - The sd2_parse_rsrc_fork function in sd2.c in libsndfile
    allows attackers to have unspecified impact via vectors
    related to a (1) map offset or (2) rsrc marker, which
    triggers an out-of-bounds read.(CVE-2014-9496)

  - The flac_buffer_copy function in flac.c in libsndfile
    1.0.28 allows remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    audio file.(CVE-2017-8361)

  - In libsndfile before 1.0.28, an error in the
    'flac_buffer_copy()' function (flac.c) can be exploited
    to cause a segmentation violation (with write memory
    access) via a specially crafted FLAC file during a
    resample attempt, a similar issue to
    CVE-2017-7585.(CVE-2017-7741)

  - In libsndfile before 1.0.28, an error in the
    'flac_buffer_copy()' function (flac.c) can be exploited
    to cause a segmentation violation (with read memory
    access) via a specially crafted FLAC file during a
    resample attempt, a similar issue to
    CVE-2017-7585.(CVE-2017-7742)

  - In libsndfile before 1.0.28, an error in the
    'flac_buffer_copy()' function (flac.c) can be exploited
    to cause a stack-based buffer overflow via a specially
    crafted FLAC file.(CVE-2017-7585)

  - An out of bounds read in the function d2ulaw_array() in
    ulaw.c of libsndfile 1.0.28 may lead to a remote DoS
    attack or information disclosure, related to
    mishandling of the NAN and INFINITY floating-point
    values.(CVE-2017-14246)

  - An out of bounds read in the function d2alaw_array() in
    alaw.c of libsndfile 1.0.28 may lead to a remote DoS
    attack or information disclosure, related to
    mishandling of the NAN and INFINITY floating-point
    values.(CVE-2017-14245)

  - The function d2ulaw_array() in ulaw.c of libsndfile
    1.0.29pre1 may lead to a remote DoS attack (SEGV on
    unknown address 0x000000000000), a different
    vulnerability than CVE-2017-14246.(CVE-2017-17457)

  - The function d2alaw_array() in alaw.c of libsndfile
    1.0.29pre1 may lead to a remote DoS attack (SEGV on
    unknown address 0x000000000000), a different
    vulnerability than CVE-2017-14245.(CVE-2017-17456)

  - In libsndfile 1.0.28, a divide-by-zero error exists in
    the function double64_init() in double64.c, which may
    lead to DoS when playing a crafted audio
    file.(CVE-2017-14634)

  - The psf_fwrite function in file_io.c in libsndfile
    allows attackers to cause a denial of service
    (divide-by-zero error and application crash) via
    unspecified vectors related to the headindex
    variable.(CVE-2014-9756)

  - In libsndfile before 1.0.28, an error in the
    'header_read()' function (common.c) when handling ID3
    tags can be exploited to cause a stack-based buffer
    overflow via a specially crafted FLAC
    file.(CVE-2017-7586)

  - The flac_buffer_copy function in flac.c in libsndfile
    1.0.28 allows remote attackers to cause a denial of
    service (invalid read and application crash) via a
    crafted audio file.(CVE-2017-8362)

  - The flac_buffer_copy function in flac.c in libsndfile
    1.0.28 allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application
    crash) via a crafted audio file.(CVE-2017-8363)

  - The i2les_array function in pcm.c in libsndfile 1.0.28
    allows remote attackers to cause a denial of service
    (buffer over-read and application crash) via a crafted
    audio file.(CVE-2017-8365)

  - In libsndfile 1.0.25 (fixed in 1.0.26), a
    divide-by-zero error exists in the function
    wav_w64_read_fmt_chunk() in wav_w64.c, which may lead
    to DoS when playing a crafted audio
    file.(CVE-2017-16942)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2208
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e665082");
  script_set_attribute(attribute:"solution", value:
"Update the affected libsndfile packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8361");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsndfile");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libsndfile-1.0.25-10.h9.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsndfile");
}
