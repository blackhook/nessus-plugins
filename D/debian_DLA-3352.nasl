#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3352. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172109);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-47664",
    "CVE-2022-47665",
    "CVE-2023-24751",
    "CVE-2023-24752",
    "CVE-2023-24754",
    "CVE-2023-24755",
    "CVE-2023-24756",
    "CVE-2023-24757",
    "CVE-2023-24758",
    "CVE-2023-25221"
  );

  script_name(english:"Debian DLA-3352-1 : libde265 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3352 advisory.

  - libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the mc_chroma function at
    motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input
    file. (CVE-2023-24751)

  - libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the
    ff_hevc_put_hevc_epel_pixels_8_sse function at sse-motion.cc. This vulnerability allows attackers to cause
    a Denial of Service (DoS) via a crafted input file. (CVE-2023-24752)

  - libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the
    ff_hevc_put_weighted_pred_avg_8_sse function at sse-motion.cc. This vulnerability allows attackers to
    cause a Denial of Service (DoS) via a crafted input file. (CVE-2023-24754, CVE-2023-24758)

  - libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the put_weighted_pred_8_fallback
    function at fallback-motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via
    a crafted input file. (CVE-2023-24755)

  - libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the
    ff_hevc_put_unweighted_pred_8_sse function at sse-motion.cc. This vulnerability allows attackers to cause
    a Denial of Service (DoS) via a crafted input file. (CVE-2023-24756)

  - libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the
    put_unweighted_pred_16_fallback function at fallback-motion.cc. This vulnerability allows attackers to
    cause a Denial of Service (DoS) via a crafted input file. (CVE-2023-24757)

  - Libde265 v1.0.10 was discovered to contain a heap-buffer-overflow vulnerability in the
    derive_spatial_luma_vector_prediction function in motion.cc. (CVE-2023-25221)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libde265");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3352");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47664");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47665");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24751");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24754");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24755");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24757");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24758");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-25221");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libde265");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libde265 packages.

For Debian 10 buster, these problems have been fixed in version 1.0.11-0+deb10u4.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libde265-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libde265-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libde265-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libde265-0', 'reference': '1.0.11-0+deb10u4'},
    {'release': '10.0', 'prefix': 'libde265-dev', 'reference': '1.0.11-0+deb10u4'},
    {'release': '10.0', 'prefix': 'libde265-examples', 'reference': '1.0.11-0+deb10u4'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libde265-0 / libde265-dev / libde265-examples');
}
