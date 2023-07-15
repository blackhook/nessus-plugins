#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148585);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id(
    "CVE-2019-19911",
    "CVE-2020-10177",
    "CVE-2020-10378",
    "CVE-2020-10379",
    "CVE-2020-10994",
    "CVE-2020-11538",
    "CVE-2020-19911",
    "CVE-2020-35653",
    "CVE-2020-5310",
    "CVE-2020-5311",
    "CVE-2020-5312",
    "CVE-2020-5313"
  );

  script_name(english:"EulerOS Virtualization 2.9.1 : python-pillow (EulerOS-SA-2021-1729)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-pillow package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - libImaging/FliDecode.c in Pillow before 6.2.2 has an
    FLI buffer overflow.(CVE-2020-5313)

  - An out-of-bounds write flaw was discovered in
    python-pillow in the way SGI RLE images are decoded. An
    application that uses python-pillow to decode untrusted
    images may be vulnerable to this flaw, which can allow
    an attacker to crash the application or potentially
    execute code on the system.(CVE-2020-5311)

  - libImaging/PcxDecode.c in Pillow before 6.2.2 has a PCX
    P mode buffer overflow.(CVE-2020-5312)

  - In libImaging/SgiRleDecode.c in Pillow through 7.0.0, a
    number of out-of-bounds reads exist in the parsing of
    SGI image files, a different issue than
    CVE-2020-5311.(CVE-2020-11538)

  - In libImaging/Jpeg2KDecode.c in Pillow before 7.1.0,
    there are multiple out-of-bounds reads via a crafted
    JP2 file.(CVE-2020-10994)

  - In libImaging/PcxDecode.c in Pillow before 7.1.0, an
    out-of-bounds read can occur when reading PCX files
    where state->shuffle is instructed to read beyond
    state->buffer.(CVE-2020-10378)

  - Pillow before 7.1.0 has multiple out-of-bounds reads in
    libImaging/FliDecode.c.(CVE-2020-10177)

  - libImaging/TiffDecode.c in Pillow before 6.2.2 has a
    TIFF decoding integer overflow, related to
    realloc.(CVE-2020-5310)

  - In Pillow before 7.1.0, there are two Buffer Overflows
    in libImaging/TiffDecode.c.(CVE-2020-10379)

  - There is a DoS vulnerability in Pillow before 6.2.2
    caused by FpxImagePlugin.py calling the range function
    on an unvalidated 32-bit integer if the number of bands
    is large. On Windows running 32-bit Python, this
    results in an OverflowError or MemoryError due to the 2
    GB limit. However, on Linux running 64-bit Python this
    results in the process being terminated by the OOM
    killer.(CVE-2019-19911)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2020-19911)

  - In Pillow before 8.1.0, PcxDecode has a buffer
    over-read when decoding a crafted PCX file because the
    user-supplied stride value is trusted for buffer
    calculations.(CVE-2020-35653)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1729
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?480a5e59");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-pillow packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-pillow");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["python3-pillow-5.3.0-4.h7.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
