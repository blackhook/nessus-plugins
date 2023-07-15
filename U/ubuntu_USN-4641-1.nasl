##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4641-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143215);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2017-15266",
    "CVE-2017-15267",
    "CVE-2017-15600",
    "CVE-2017-15601",
    "CVE-2017-15602",
    "CVE-2017-15922",
    "CVE-2017-17440",
    "CVE-2018-14346",
    "CVE-2018-14347",
    "CVE-2018-16430",
    "CVE-2018-20430",
    "CVE-2018-20431"
  );
  script_bugtraq_id(
    101271,
    101272,
    101529,
    101534,
    101536,
    101595,
    102116,
    105254,
    106300
  );
  script_xref(name:"USN", value:"4641-1");

  script_name(english:"Ubuntu 16.04 LTS : libextractor vulnerabilities (USN-4641-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4641-1 advisory.

  - In GNU Libextractor 1.4, there is a Divide-By-Zero in EXTRACTOR_wav_extract_method in wav_extractor.c via
    a zero sample rate. (CVE-2017-15266)

  - In GNU Libextractor 1.4, there is a NULL Pointer Dereference in flac_metadata in flac_extractor.c.
    (CVE-2017-15267)

  - In GNU Libextractor 1.4, there is a NULL Pointer Dereference in the EXTRACTOR_nsf_extract_method function
    of plugins/nsf_extractor.c. (CVE-2017-15600)

  - In GNU Libextractor 1.4, there is a heap-based buffer overflow in the EXTRACTOR_png_extract_method
    function in plugins/png_extractor.c, related to processiTXt and stndup. (CVE-2017-15601)

  - In GNU Libextractor 1.4, there is an integer signedness error for the chunk size in the
    EXTRACTOR_nsfe_extract_method function in plugins/nsfe_extractor.c, leading to an infinite loop for a
    crafted size. (CVE-2017-15602)

  - In GNU Libextractor 1.4, there is an out-of-bounds read in the EXTRACTOR_dvi_extract_method function in
    plugins/dvi_extractor.c. (CVE-2017-15922)

  - GNU Libextractor 1.6 allows remote attackers to cause a denial of service (NULL pointer dereference and
    application crash) via a crafted GIF, IT (Impulse Tracker), NSFE, S3M (Scream Tracker 3), SID, or XM
    (eXtended Module) file, as demonstrated by the EXTRACTOR_xm_extract_method function in
    plugins/xm_extractor.c. (CVE-2017-17440)

  - GNU Libextractor before 1.7 has a stack-based buffer overflow in ec_read_file_func (unzip.c).
    (CVE-2018-14346)

  - GNU Libextractor before 1.7 contains an infinite loop vulnerability in EXTRACTOR_mpeg_extract_method
    (mpeg_extractor.c). (CVE-2018-14347)

  - GNU Libextractor through 1.7 has an out-of-bounds read vulnerability in EXTRACTOR_zip_extract_method() in
    zip_extractor.c. (CVE-2018-16430)

  - GNU Libextractor through 1.8 has an out-of-bounds read vulnerability in the function history_extract() in
    plugins/ole2_extractor.c, related to EXTRACTOR_common_convert_to_utf8 in common/convert.c.
    (CVE-2018-20430)

  - GNU Libextractor through 1.8 has a NULL Pointer Dereference vulnerability in the function
    process_metadata() in plugins/ole2_extractor.c. (CVE-2018-20431)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4641-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected extract, libextractor-dev and / or libextractor3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16430");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:extract");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libextractor-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libextractor3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'extract', 'pkgver': '1:1.3-4+deb9u3build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libextractor-dev', 'pkgver': '1:1.3-4+deb9u3build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libextractor3', 'pkgver': '1:1.3-4+deb9u3build0.16.04.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'extract / libextractor-dev / libextractor3');
}