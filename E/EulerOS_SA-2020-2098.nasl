#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140865);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-6827",
    "CVE-2017-6828",
    "CVE-2017-6829",
    "CVE-2017-6830",
    "CVE-2017-6831",
    "CVE-2017-6832",
    "CVE-2017-6833",
    "CVE-2017-6834",
    "CVE-2017-6835",
    "CVE-2017-6836",
    "CVE-2017-6837",
    "CVE-2017-6838",
    "CVE-2017-6839",
    "CVE-2018-13440",
    "CVE-2018-17095"
  );

  script_name(english:"EulerOS 2.0 SP3 : audiofile (EulerOS-SA-2020-2098)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the audiofile package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The audiofile Audio File Library 0.3.6 has a NULL
    pointer dereference bug in ModuleState::setup in
    modules/ModuleState.cpp, which allows an attacker to
    cause a denial of service via a crafted caf file, as
    demonstrated by sfconvert.(CVE-2018-13440)

  - An issue has been discovered in mpruett Audio File
    Library (aka audiofile) 0.3.6. A heap-based buffer
    overflow in Expand3To4Module::run has occurred when
    running sfconvert.(CVE-2018-17095)

  - Heap-based buffer overflow in the
    MSADPCM::initializeCoefficients function in MSADPCM.cpp
    in audiofile (aka libaudiofile and Audio File Library)
    0.3.6 allows remote attackers to have unspecified
    impact via a crafted audio file.(CVE-2017-6827)

  - Heap-based buffer overflow in the readValue function in
    FileHandle.cpp in audiofile (aka libaudiofile and Audio
    File Library) 0.3.6 allows remote attackers to have
    unspecified impact via a crafted WAV
    file.(CVE-2017-6828)

  - The decodeSample function in IMA.cpp in Audio File
    Library (aka audiofile) 0.3.6 allows remote attackers
    to cause a denial of service (crash) via a crafted
    file.(CVE-2017-6829)

  - Heap-based buffer overflow in the alaw2linear_buf
    function in G711.cpp in Audio File Library (aka
    audiofile) 0.3.6 allows remote attackers to cause a
    denial of service (crash) via a crafted
    file.(CVE-2017-6830)

  - Heap-based buffer overflow in the decodeBlockWAVE
    function in IMA.cpp in Audio File Library (aka
    audiofile) 0.3.6 allows remote attackers to cause a
    denial of service (crash) via a crafted
    file.(CVE-2017-6831)

  - Heap-based buffer overflow in the decodeBlock in
    MSADPCM.cpp in Audio File Library (aka audiofile) 0.3.6
    allows remote attackers to cause a denial of service
    (crash) via a crafted file.(CVE-2017-6832)

  - The runPull function in
    libaudiofile/modules/BlockCodec.cpp in Audio File
    Library (aka audiofile) 0.3.6 allows remote attackers
    to cause a denial of service (divide-by-zero error and
    crash) via a crafted file.(CVE-2017-6833)

  - Heap-based buffer overflow in the ulaw2linear_buf
    function in G711.cpp in Audio File Library (aka
    audiofile) 0.3.6 allows remote attackers to cause a
    denial of service (crash) via a crafted
    file.(CVE-2017-6834)

  - The reset1 function in
    libaudiofile/modules/BlockCodec.cpp in Audio File
    Library (aka audiofile) 0.3.6 allows remote attackers
    to cause a denial of service (divide-by-zero error and
    crash) via a crafted file.(CVE-2017-6835)

  - Heap-based buffer overflow in the Expand3To4Module::run
    function in libaudiofile/modules/SimpleModule.h in
    Audio File Library (aka audiofile) 0.3.6 allows remote
    attackers to cause a denial of service (crash) via a
    crafted file.(CVE-2017-6836)

  - WAVE.cpp in Audio File Library (aka audiofile) 0.3.6
    allows remote attackers to cause a denial of service
    (crash) via vectors related to a large number of
    coefficients.(CVE-2017-6837)

  - Integer overflow in sfcommands/sfconvert.c in Audio
    File Library (aka audiofile) 0.3.6 allows remote
    attackers to cause a denial of service (crash) via a
    crafted file.(CVE-2017-6838)

  - Integer overflow in modules/MSADPCM.cpp in Audio File
    Library (aka audiofile) 0.3.6 allows remote attackers
    to cause a denial of service (crash) via a crafted
    file.(CVE-2017-6839)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f260bae");
  script_set_attribute(attribute:"solution", value:
"Update the affected audiofile packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17095");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:audiofile");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["audiofile-0.3.6-4.h2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "audiofile");
}
