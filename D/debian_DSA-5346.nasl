#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5346. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171376);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/11");

  script_cve_id(
    "CVE-2020-21594",
    "CVE-2020-21595",
    "CVE-2020-21596",
    "CVE-2020-21597",
    "CVE-2020-21598",
    "CVE-2020-21599",
    "CVE-2020-21600",
    "CVE-2020-21601",
    "CVE-2020-21602",
    "CVE-2020-21603",
    "CVE-2020-21604",
    "CVE-2020-21605",
    "CVE-2020-21606",
    "CVE-2021-35452",
    "CVE-2021-36408",
    "CVE-2021-36409",
    "CVE-2021-36410",
    "CVE-2021-36411",
    "CVE-2022-1253",
    "CVE-2022-43235",
    "CVE-2022-43236",
    "CVE-2022-43237",
    "CVE-2022-43238",
    "CVE-2022-43239",
    "CVE-2022-43240",
    "CVE-2022-43241",
    "CVE-2022-43242",
    "CVE-2022-43243",
    "CVE-2022-43244",
    "CVE-2022-43245",
    "CVE-2022-43248",
    "CVE-2022-43249",
    "CVE-2022-43250",
    "CVE-2022-43252",
    "CVE-2022-43253",
    "CVE-2022-47655"
  );

  script_name(english:"Debian DSA-5346-1 : libde265 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5346 advisory.

  - libde265 v1.0.4 contains a heap buffer overflow in the put_epel_hv_fallback function, which can be
    exploited via a crafted a file. (CVE-2020-21594)

  - libde265 v1.0.4 contains a heap buffer overflow in the mc_luma function, which can be exploited via a
    crafted a file. (CVE-2020-21595)

  - libde265 v1.0.4 contains a global buffer overflow in the decode_CABAC_bit function, which can be exploited
    via a crafted a file. (CVE-2020-21596)

  - libde265 v1.0.4 contains a heap buffer overflow in the mc_chroma function, which can be exploited via a
    crafted a file. (CVE-2020-21597)

  - libde265 v1.0.4 contains a heap buffer overflow in the ff_hevc_put_unweighted_pred_8_sse function, which
    can be exploited via a crafted a file. (CVE-2020-21598)

  - libde265 v1.0.4 contains a heap buffer overflow in the de265_image::available_zscan function, which can be
    exploited via a crafted a file. (CVE-2020-21599)

  - libde265 v1.0.4 contains a heap buffer overflow in the put_weighted_pred_avg_16_fallback function, which
    can be exploited via a crafted a file. (CVE-2020-21600)

  - libde265 v1.0.4 contains a stack buffer overflow in the put_qpel_fallback function, which can be exploited
    via a crafted a file. (CVE-2020-21601)

  - libde265 v1.0.4 contains a heap buffer overflow in the put_weighted_bipred_16_fallback function, which can
    be exploited via a crafted a file. (CVE-2020-21602)

  - libde265 v1.0.4 contains a heap buffer overflow in the put_qpel_0_0_fallback_16 function, which can be
    exploited via a crafted a file. (CVE-2020-21603)

  - libde265 v1.0.4 contains a heap buffer overflow fault in the _mm_loadl_epi64 function, which can be
    exploited via a crafted a file. (CVE-2020-21604)

  - libde265 v1.0.4 contains a segmentation fault in the apply_sao_internal function, which can be exploited
    via a crafted a file. (CVE-2020-21605)

  - libde265 v1.0.4 contains a heap buffer overflow fault in the put_epel_16_fallback function, which can be
    exploited via a crafted a file. (CVE-2020-21606)

  - An Incorrect Access Control vulnerability exists in libde265 v1.0.8 due to a SEGV in slice.cc.
    (CVE-2021-35452)

  - An issue was discovered in libde265 v1.0.8.There is a Heap-use-after-free in intrapred.h when decoding
    file using dec265. (CVE-2021-36408)

  - There is an Assertion `scaling_list_pred_matrix_id_delta==1' failed at sps.cc:925 in libde265 v1.0.8 when
    decoding file, which allows attackers to cause a Denial of Service (DoS) by running the application with a
    crafted file or possibly have unspecified other impact. (CVE-2021-36409)

  - A stack-buffer-overflow exists in libde265 v1.0.8 via fallback-motion.cc in function put_epel_hv_fallback
    when running program dec265. (CVE-2021-36410)

  - An issue has been found in libde265 v1.0.8 due to incorrect access control. A SEGV caused by a READ memory
    access in function derive_boundaryStrength of deblock.cc has occurred. The vulnerability causes a
    segmentation fault and application crash, which leads to remote denial of service. (CVE-2021-36411)

  - Heap-based Buffer Overflow in GitHub repository strukturag/libde265 prior to and including 1.0.8. The fix
    is established in commit 8e89fe0e175d2870c39486fdd09250b230ec10b8 but does not yet belong to an official
    release. (CVE-2022-1253)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via
    ff_hevc_put_hevc_epel_pixels_8_sse in sse-motion.cc. This vulnerability allows attackers to cause a Denial
    of Service (DoS) via a crafted video file. (CVE-2022-43235)

  - Libde265 v1.0.8 was discovered to contain a stack-buffer-overflow vulnerability via
    put_qpel_fallback<unsigned short> in fallback-motion.cc. This vulnerability allows attackers to cause a
    Denial of Service (DoS) via a crafted video file. (CVE-2022-43236)

  - Libde265 v1.0.8 was discovered to contain a stack-buffer-overflow vulnerability via void
    put_epel_hv_fallback<unsigned short> in fallback-motion.cc. This vulnerability allows attackers to cause a
    Denial of Service (DoS) via a crafted video file. (CVE-2022-43237)

  - Libde265 v1.0.8 was discovered to contain an unknown crash via ff_hevc_put_hevc_qpel_h_3_v_3_sse in sse-
    motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted video
    file. (CVE-2022-43238)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via mc_chroma<unsigned
    short> in motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted
    video file. (CVE-2022-43239)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via
    ff_hevc_put_hevc_qpel_h_2_v_1_sse in sse-motion.cc. This vulnerability allows attackers to cause a Denial
    of Service (DoS) via a crafted video file. (CVE-2022-43240)

  - Libde265 v1.0.8 was discovered to contain an unknown crash via ff_hevc_put_hevc_qpel_v_3_8_sse in sse-
    motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted video
    file. (CVE-2022-43241)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via mc_luma<unsigned char>
    in motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted video
    file. (CVE-2022-43242)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via
    ff_hevc_put_weighted_pred_avg_8_sse in sse-motion.cc. This vulnerability allows attackers to cause a
    Denial of Service (DoS) via a crafted video file. (CVE-2022-43243)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via
    put_qpel_fallback<unsigned short> in fallback-motion.cc. This vulnerability allows attackers to cause a
    Denial of Service (DoS) via a crafted video file. (CVE-2022-43244)

  - Libde265 v1.0.8 was discovered to contain a segmentation violation via apply_sao_internal<unsigned short>
    in sao.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted video
    file. (CVE-2022-43245)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via
    put_weighted_pred_avg_16_fallback in fallback-motion.cc. This vulnerability allows attackers to cause a
    Denial of Service (DoS) via a crafted video file. (CVE-2022-43248)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via
    put_epel_hv_fallback<unsigned short> in fallback-motion.cc. This vulnerability allows attackers to cause a
    Denial of Service (DoS) via a crafted video file. (CVE-2022-43249)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via
    put_qpel_0_0_fallback_16 in fallback-motion.cc. This vulnerability allows attackers to cause a Denial of
    Service (DoS) via a crafted video file. (CVE-2022-43250)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via put_epel_16_fallback in
    fallback-motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted
    video file. (CVE-2022-43252)

  - Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow vulnerability via
    put_unweighted_pred_16_fallback in fallback-motion.cc. This vulnerability allows attackers to cause a
    Denial of Service (DoS) via a crafted video file. (CVE-2022-43253)

  - Libde265 1.0.9 is vulnerable to Buffer Overflow in function void put_qpel_fallback<unsigned short>
    (CVE-2022-47655)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1004963");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libde265");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5346");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21595");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21596");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21603");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21604");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21605");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-35452");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36408");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36409");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36410");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36411");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1253");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43235");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43236");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43237");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43238");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43239");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43240");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43241");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43242");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43243");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43245");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43248");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43249");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43250");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43252");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43253");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47655");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libde265");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libde265 packages.

For the stable distribution (bullseye), these problems have been fixed in version 1.0.11-0+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1253");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libde265-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libde265-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libde265-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libde265-0', 'reference': '1.0.11-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libde265-dev', 'reference': '1.0.11-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libde265-examples', 'reference': '1.0.11-0+deb11u1'}
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
