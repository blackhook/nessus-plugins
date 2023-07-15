#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146720);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_cve_id(
    "CVE-2017-11332",
    "CVE-2017-11358",
    "CVE-2017-11359",
    "CVE-2017-15370",
    "CVE-2017-15371",
    "CVE-2017-15372",
    "CVE-2017-15642",
    "CVE-2019-13590",
    "CVE-2019-8355",
    "CVE-2019-8356",
    "CVE-2019-8357"
  );

  script_name(english:"EulerOS 2.0 SP2 : sox (EulerOS-SA-2021-1359)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the sox package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in SoX 14.4.2. In xmalloc.h,
    there is an integer overflow on the result of
    multiplication fed into the lsx_valloc macro that wraps
    malloc. When the buffer is allocated, it is smaller
    than expected, leading to a heap-based buffer overflow
    in channels_start in remix.c.(CVE-2019-8355)

  - An issue was discovered in SoX 14.4.2. One of the
    arguments to bitrv2 in fft4g.c is not guarded, such
    that it can lead to write access outside of the
    statically declared array, aka a stack-based buffer
    overflow.(CVE-2019-8356)

  - An issue was discovered in SoX 14.4.2. lsx_make_lpf in
    effect_i_dsp.c allows a NULL pointer
    dereference.(CVE-2019-8357)

  - An issue was discovered in libsox.a in SoX 14.4.2. In
    sox-fmt.h (startread function), there is an integer
    overflow on the result of integer addition (wraparound
    to 0) fed into the lsx_calloc macro that wraps malloc.
    When a NULL pointer is returned, it is used without a
    prior check that it is a valid pointer, leading to a
    NULL pointer dereference on lsx_readbuf in
    formats_i.c.(CVE-2019-13590)

  - The startread function in wav.c in Sound eXchange (SoX)
    14.4.2 allows remote attackers to cause a denial of
    service (divide-by-zero error and application crash)
    via a crafted wav file.(CVE-2017-11332)

  - The read_samples function in hcom.c in Sound eXchange
    (SoX) 14.4.2 allows remote attackers to cause a denial
    of service (invalid memory read and application crash)
    via a crafted hcom file.(CVE-2017-11358)

  - The wavwritehdr function in wav.c in Sound eXchange
    (SoX) 14.4.2 allows remote attackers to cause a denial
    of service (divide-by-zero error and application crash)
    via a crafted snd file, during conversion to a wav
    file.(CVE-2017-11359)

  - There is a heap-based buffer overflow in the ImaExpandS
    function of ima_rw.c in Sound eXchange (SoX) 14.4.2. A
    Crafted input will lead to a denial of service attack
    during conversion of an audio file.(CVE-2017-15370)

  - There is a reachable assertion abort in the function
    sox_append_comment() in formats.c in Sound eXchange
    (SoX) 14.4.2. A Crafted input will lead to a denial of
    service attack during conversion of an audio
    file.(CVE-2017-15371)

  - There is a stack-based buffer overflow in the
    lsx_ms_adpcm_block_expand_i function of adpcm.c in
    Sound eXchange (SoX) 14.4.2. A Crafted input will lead
    to a denial of service attack during conversion of an
    audio file.(CVE-2017-15372)

  - In lsx_aiffstartread in aiff.c in Sound eXchange (SoX)
    14.4.2, there is a Use-After-Free vulnerability
    triggered by supplying a malformed AIFF
    file.(CVE-2017-15642)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1359
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?212916b4");
  script_set_attribute(attribute:"solution", value:
"Update the affected sox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sox");
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

pkgs = ["sox-14.4.1-6.h3"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sox");
}
