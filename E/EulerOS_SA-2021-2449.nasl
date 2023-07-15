#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153259);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/16");

  script_cve_id(
    "CVE-2017-9258",
    "CVE-2017-9259",
    "CVE-2017-9260",
    "CVE-2018-1000223",
    "CVE-2018-14044",
    "CVE-2018-17096"
  );

  script_name(english:"EulerOS 2.0 SP2 : soundtouch (EulerOS-SA-2021-2449)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the soundtouch package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The BPMDetect class in BPMDetect.cpp in libSoundTouch.a
    in Olli Parviainen SoundTouch 2.0 allows remote
    attackers to cause a denial of service (assertion
    failure and application exit), as demonstrated by
    SoundStretch.(CVE-2018-17096)

  - The TDStretchSSE::calcCrossCorr function in
    source/SoundTouch/sse_optimized.cpp in SoundTouch 1.9.2
    allows remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) via
    a crafted wav file.(CVE-2017-9260)

  - The TDStretch::processSamples function in
    source/SoundTouch/TDStretch.cpp in SoundTouch 1.9.2
    allows remote attackers to cause a denial of service
    (infinite loop and CPU consumption) via a crafted wav
    file.(CVE-2017-9258)

  - The TDStretch::acceptNewOverlapLength function in
    source/SoundTouch/TDStretch.cpp in SoundTouch 1.9.2
    allows remote attackers to cause a denial of service
    (memory allocation error and application crash) via a
    crafted wav file.(CVE-2017-9259)

  - The RateTransposer::setChannels function in
    RateTransposer.cpp in libSoundTouch.a in Olli
    Parviainen SoundTouch 2.0 allows remote attackers to
    cause a denial of service (assertion failure and
    application exit), as demonstrated by
    SoundStretch.(CVE-2018-14044)

  - soundtouch version up to and including 2.0.0 contains a
    Buffer Overflow vulnerability in
    SoundStretch/WavFile.cpp:WavInFile::readHeaderBlock()
    that can result in arbitrary code execution. This
    attack appear to be exploitable via victim must open
    maliocius file in soundstretch
    utility.(CVE-2018-1000223)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2449
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed56a8a5");
  script_set_attribute(attribute:"solution", value:
"Update the affected soundtouch packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000223");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:soundtouch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["soundtouch-1.4.0-9.h3"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "soundtouch");
}
