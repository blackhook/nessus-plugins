#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160170);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2020-4030",
    "CVE-2020-11017",
    "CVE-2020-11018",
    "CVE-2020-11019",
    "CVE-2020-11038",
    "CVE-2020-11040",
    "CVE-2020-11041",
    "CVE-2020-11058",
    "CVE-2020-11086",
    "CVE-2020-11087",
    "CVE-2020-11088",
    "CVE-2020-11521",
    "CVE-2020-11523",
    "CVE-2020-11525",
    "CVE-2020-11526",
    "CVE-2020-13397",
    "CVE-2020-15103"
  );

  script_name(english:"EulerOS 2.0 SP8 : freerdp (EulerOS-SA-2022-1564)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the freerdp packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - In FreeRDP less than or equal to 2.0.0, by providing manipulated input a malicious client can create a
    double free condition and crash the server. This is fixed in version 2.1.0. (CVE-2020-11017)

  - In FreeRDP less than or equal to 2.0.0, a possible resource exhaustion vulnerability can be performed.
    Malicious clients could trigger out of bound reads causing memory allocation with random size. This has
    been fixed in 2.1.0. (CVE-2020-11018)

  - In FreeRDP less than or equal to 2.0.0, when running with logger set to 'WLOG_TRACE', a possible crash of
    application could occur due to a read of an invalid array index. Data could be printed as string to local
    terminal. This has been fixed in 2.1.0. (CVE-2020-11019)

  - In FreeRDP less than or equal to 2.0.0, an Integer Overflow to Buffer Overflow exists. When using /video
    redirection, a manipulated server can instruct the client to allocate a buffer with a smaller size than
    requested due to an integer overflow in size calculation. With later messages, the server can manipulate
    the client to write data out of bound to the previously allocated buffer. This has been patched in 2.1.0.
    (CVE-2020-11038)

  - In FreeRDP less than or equal to 2.0.0, there is an out-of-bound data read from memory in
    clear_decompress_subcode_rlex, visualized on screen as color. This has been patched in 2.1.0.
    (CVE-2020-11040)

  - In FreeRDP less than or equal to 2.0.0, an outside controlled array index is used unchecked for data used
    as configuration for sound backend (alsa, oss, pulse, ...). The most likely outcome is a crash of the
    client instance followed by no or distorted sound or a session disconnect. If a user cannot upgrade to the
    patched version, a workaround is to disable sound for the session. This has been patched in 2.1.0.
    (CVE-2020-11041)

  - In FreeRDP after 1.1 and before 2.0.0, a stream out-of-bounds seek in rdp_read_font_capability_set could
    lead to a later out-of-bounds read. As a result, a manipulated client or server might force a disconnect
    due to an invalid data read. This has been fixed in 2.0.0. (CVE-2020-11058)

  - In FreeRDP less than or equal to 2.0.0, there is an out-of-bound read in
    ntlm_read_ntlm_v2_client_challenge that reads up to 28 bytes out-of-bound to an internal structure. This
    has been fixed in 2.1.0. (CVE-2020-11086)

  - In FreeRDP less than or equal to 2.0.0, there is an out-of-bound read in ntlm_read_AuthenticateMessage.
    This has been fixed in 2.1.0. (CVE-2020-11087)

  - In FreeRDP less than or equal to 2.0.0, there is an out-of-bound read in ntlm_read_NegotiateMessage. This
    has been fixed in 2.1.0. (CVE-2020-11088)

  - libfreerdp/codec/planar.c in FreeRDP version > 1.0 through 2.0.0-rc4 has an Out-of-bounds Write.
    (CVE-2020-11521)

  - libfreerdp/gdi/region.c in FreeRDP versions > 1.0 through 2.0.0-rc4 has an Integer Overflow.
    (CVE-2020-11523)

  - libfreerdp/cache/bitmap.c in FreeRDP versions > 1.0 through 2.0.0-rc4 has an Out of bounds read.
    (CVE-2020-11525)

  - libfreerdp/core/update.c in FreeRDP versions > 1.1 through 2.0.0-rc4 has an Out-of-bounds Read.
    (CVE-2020-11526)

  - An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds (OOB) read vulnerability has been
    detected in security_fips_decrypt in libfreerdp/core/security.c due to an uninitialized value.
    (CVE-2020-13397)

  - In FreeRDP less than or equal to 2.1.2, an integer overflow exists due to missing input sanitation in
    rdpegfx channel. All FreeRDP clients are affected. The input rectangles from the server are not checked
    against local surface coordinates and blindly accepted. A malicious server can send data that will crash
    the client later on (invalid length arguments to a `memcpy`) This has been fixed in 2.2.0. As a
    workaround, stop using command line arguments /gfx, /gfx-h264 and /network:auto (CVE-2020-15103)

  - In FreeRDP before version 2.1.2, there is an out of bounds read in TrioParse. Logging might bypass string
    length checks due to an integer overflow. This is fixed in version 2.1.2. (CVE-2020-4030)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1564
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18404db");
  script_set_attribute(attribute:"solution", value:
"Update the affected freerdp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4030");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-11523");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwinpr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "freerdp-2.0.0-44.rc3.h11.eulerosv2r8",
  "freerdp-libs-2.0.0-44.rc3.h11.eulerosv2r8",
  "libwinpr-2.0.0-44.rc3.h11.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp");
}
