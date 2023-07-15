#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146238);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id(
    "CVE-2019-16865",
    "CVE-2019-19911",
    "CVE-2020-10177",
    "CVE-2020-10378",
    "CVE-2020-10379",
    "CVE-2020-10994",
    "CVE-2020-11538",
    "CVE-2020-35653",
    "CVE-2020-5310",
    "CVE-2020-5311",
    "CVE-2020-5312",
    "CVE-2020-5313"
  );

  script_name(english:"EulerOS 2.0 SP9 : python-pillow (EulerOS-SA-2021-1273)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-pillow packages installed,
the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - In Pillow before 8.1.0, PcxDecode has a buffer
    over-read when decoding a crafted PCX file because the
    user-supplied stride value is trusted for buffer
    calculations.(CVE-2020-35653)

  - libImaging/FliDecode.c in Pillow before 6.2.2 has an
    FLI buffer overflow.(CVE-2020-5313)

  - In libImaging/Jpeg2KDecode.c in Pillow before 7.1.0,
    there are multiple out-of-bounds reads via a crafted
    JP2 file.(CVE-2020-10994)

  - In libImaging/SgiRleDecode.c in Pillow through 7.0.0, a
    number of out-of-bounds reads exist in the parsing of
    SGI image files, a different issue than
    CVE-2020-5311.(CVE-2020-11538)

  - There is a DoS vulnerability in Pillow before 6.2.2
    caused by FpxImagePlugin.py calling the range function
    on an unvalidated 32-bit integer if the number of bands
    is large. On Windows running 32-bit Python, this
    results in an OverflowError or MemoryError due to the 2
    GB limit. However, on Linux running 64-bit Python this
    results in the process being terminated by the OOM
    killer.(CVE-2019-19911)

  - libImaging/TiffDecode.c in Pillow before 6.2.2 has a
    TIFF decoding integer overflow, related to
    realloc.(CVE-2020-5310)

  - An out-of-bounds write flaw was discovered in
    python-pillow in the way SGI RLE images are decoded. An
    application that uses python-pillow to decode untrusted
    images may be vulnerable to this flaw, which can allow
    an attacker to crash the application or potentially
    execute code on the system.(CVE-2020-5311)

  - libImaging/PcxDecode.c in Pillow before 6.2.2 has a PCX
    P mode buffer overflow.(CVE-2020-5312)

  - In Pillow before 7.1.0, there are two Buffer Overflows
    in libImaging/TiffDecode.c.(CVE-2020-10379)

  - An issue was discovered in Pillow before 6.2.0. When
    reading specially crafted invalid image files, the
    library can either allocate very large amounts of
    memory or take an extremely long period of time to
    process the image.(CVE-2019-16865)

  - In libImaging/PcxDecode.c in Pillow before 7.1.0, an
    out-of-bounds read can occur when reading PCX files
    where state->shuffle is instructed to read beyond
    state->buffer.(CVE-2020-10378)

  - Pillow before 7.1.0 has multiple out-of-bounds reads in
    libImaging/FliDecode.c.(CVE-2020-10177)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1273
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9513f4ca");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-pillow packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-pillow");
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
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["python-pillow-5.3.0-4.h7.eulerosv2r9",
        "python3-pillow-5.3.0-4.h7.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pillow");
}
