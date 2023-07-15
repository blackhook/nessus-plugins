##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0063. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160811);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-4030",
    "CVE-2020-4033",
    "CVE-2020-11095",
    "CVE-2020-11096",
    "CVE-2020-11097",
    "CVE-2020-11098",
    "CVE-2020-11099",
    "CVE-2020-15103"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : freerdp Multiple Vulnerabilities (NS-SA-2022-0063)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has freerdp packages installed that are affected by multiple
vulnerabilities:

  - In FreeRDP before version 2.1.2, an out of bound reads occurs resulting in accessing a memory location
    that is outside of the boundaries of the static array PRIMARY_DRAWING_ORDER_FIELD_BYTES. This is fixed in
    version 2.1.2. (CVE-2020-11095)

  - In FreeRDP before version 2.1.2, there is a global OOB read in update_read_cache_bitmap_v3_order. As a
    workaround, one can disable bitmap cache with -bitmap-cache (default). This is fixed in version 2.1.2.
    (CVE-2020-11096)

  - In FreeRDP before version 2.1.2, an out of bounds read occurs resulting in accessing a memory location
    that is outside of the boundaries of the static array PRIMARY_DRAWING_ORDER_FIELD_BYTES. This is fixed in
    version 2.1.2. (CVE-2020-11097)

  - In FreeRDP before version 2.1.2, there is an out-of-bound read in glyph_cache_put. This affects all
    FreeRDP clients with `+glyph-cache` option enabled This is fixed in version 2.1.2. (CVE-2020-11098)

  - In FreeRDP before version 2.1.2, there is an out of bounds read in
    license_read_new_or_upgrade_license_packet. A manipulated license packet can lead to out of bound reads to
    an internal buffer. This is fixed in version 2.1.2. (CVE-2020-11099)

  - In FreeRDP less than or equal to 2.1.2, an integer overflow exists due to missing input sanitation in
    rdpegfx channel. All FreeRDP clients are affected. The input rectangles from the server are not checked
    against local surface coordinates and blindly accepted. A malicious server can send data that will crash
    the client later on (invalid length arguments to a `memcpy`) This has been fixed in 2.2.0. As a
    workaround, stop using command line arguments /gfx, /gfx-h264 and /network:auto (CVE-2020-15103)

  - In FreeRDP before version 2.1.2, there is an out of bounds read in TrioParse. Logging might bypass string
    length checks due to an integer overflow. This is fixed in version 2.1.2. (CVE-2020-4030)

  - In FreeRDP before version 2.1.2, there is an out of bounds read in RLEDECOMPRESS. All FreeRDP based
    clients with sessions with color depth < 32 are affected. This is fixed in version 2.1.2. (CVE-2020-4033)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0063");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11095");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11096");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11097");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11098");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11099");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15103");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-4030");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-4033");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL freerdp packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4033");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwinpr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwinpr-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'freerdp-2.2.0-1.el8',
    'freerdp-debuginfo-2.2.0-1.el8',
    'freerdp-debugsource-2.2.0-1.el8',
    'freerdp-devel-2.2.0-1.el8',
    'freerdp-libs-2.2.0-1.el8',
    'freerdp-libs-debuginfo-2.2.0-1.el8',
    'libwinpr-2.2.0-1.el8',
    'libwinpr-debuginfo-2.2.0-1.el8',
    'libwinpr-devel-2.2.0-1.el8'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp');
}
