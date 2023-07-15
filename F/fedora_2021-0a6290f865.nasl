##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-0a6290f865
#

include('compat.inc');

if (description)
{
  script_id(146125);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_cve_id(
    "CVE-2016-9396",
    "CVE-2016-9397",
    "CVE-2016-9398",
    "CVE-2016-9399",
    "CVE-2017-1000050",
    "CVE-2017-13745",
    "CVE-2017-13746",
    "CVE-2017-13747",
    "CVE-2017-13748",
    "CVE-2017-13749",
    "CVE-2017-13750",
    "CVE-2017-13751",
    "CVE-2017-13752",
    "CVE-2017-14132",
    "CVE-2020-27828"
  );
  script_xref(name:"FEDORA", value:"2021-0a6290f865");

  script_name(english:"Fedora 32 : jasper (2021-0a6290f865)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 32 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2021-0a6290f865 advisory.

  - The JPC_NOMINALGAIN function in jpc/jpc_t1cod.c in JasPer through 2.0.12 allows remote attackers to cause
    a denial of service (JPC_COX_RFT assertion failure) via unspecified vectors. (CVE-2016-9396)

  - The jpc_dequantize function in jpc_dec.c in JasPer 1.900.13 allows remote attackers to cause a denial of
    service (assertion failure) via unspecified vectors. (CVE-2016-9397)

  - The jpc_floorlog2 function in jpc_math.c in JasPer before 1.900.17 allows remote attackers to cause a
    denial of service (assertion failure) via unspecified vectors. (CVE-2016-9398)

  - The calcstepsizes function in jpc_dec.c in JasPer 1.900.22 allows remote attackers to cause a denial of
    service (assertion failure) via unspecified vectors. (CVE-2016-9399)

  - There is a reachable assertion abort in the function jpc_dec_process_sot() in jpc/jpc_dec.c in JasPer
    2.0.12 that will lead to a remote denial of service attack by triggering an unexpected
    jpc_ppmstabtostreams return value, a different vulnerability than CVE-2018-9154. (CVE-2017-13745)

  - There is a reachable assertion abort in the function jpc_dec_process_siz() in jpc/jpc_dec.c:1297 in JasPer
    2.0.12 that will lead to a remote denial of service attack. (CVE-2017-13746)

  - There is a reachable assertion abort in the function jpc_floorlog2() in jpc/jpc_math.c in JasPer 2.0.12
    that will lead to a remote denial of service attack. (CVE-2017-13747)

  - There are lots of memory leaks in JasPer 2.0.12, triggered in the function jas_strdup() in
    base/jas_string.c, that will lead to a remote denial of service attack. (CVE-2017-13748)

  - There is a reachable assertion abort in the function jpc_pi_nextrpcl() in jpc/jpc_t2cod.c in JasPer 2.0.12
    that will lead to a remote denial of service attack. (CVE-2017-13749)

  - There is a reachable assertion abort in the function jpc_dec_process_siz() in jpc/jpc_dec.c:1296 in JasPer
    2.0.12 that will lead to a remote denial of service attack. (CVE-2017-13750)

  - There is a reachable assertion abort in the function calcstepsizes() in jpc/jpc_dec.c in JasPer 2.0.12
    that will lead to a remote denial of service attack. (CVE-2017-13751)

  - There is a reachable assertion abort in the function jpc_dequantize() in jpc/jpc_dec.c in JasPer 2.0.12
    that will lead to a remote denial of service attack. (CVE-2017-13752)

  - JasPer 1.900.8, 1.900.9, 1.900.10, 1.900.11, 1.900.12, 1.900.13, 1.900.14, 1.900.15, 1.900.16, 1.900.17,
    1.900.18, 1.900.19, 1.900.20, 1.900.21, 1.900.22, 1.900.23, 1.900.24, 1.900.25, 1.900.26, 1.900.27,
    1.900.28, 1.900.29, 1.900.30, 1.900.31, 2.0.0, 2.0.1, 2.0.2, 2.0.3, 2.0.4, 2.0.5, 2.0.6, 2.0.7, 2.0.8,
    2.0.9, 2.0.10, 2.0.11, 2.0.12, 2.0.13, 2.0.14, 2.0.15, 2.0.16 allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application crash) via a crafted image, related to the
    jas_image_ishomosamp function in libjasper/base/jas_image.c. (CVE-2017-14132)

  - JasPer 2.0.12 is vulnerable to a NULL pointer exception in the function jp2_encode which failed to check
    to see if the image contained at least one component resulting in a denial-of-service. (CVE-2017-1000050)

  - There's a flaw in jasper's jpc encoder in versions prior to 2.0.23. Crafted input provided to jasper by an
    attacker could cause an arbitrary out-of-bounds write. This could potentially affect data confidentiality,
    integrity, or application availability. (CVE-2020-27828)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-0a6290f865");
  script_set_attribute(attribute:"solution", value:
"Update the affected jasper package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27828");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jasper");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Fedora' >!< release) audit(AUDIT_OS_NOT, 'Fedora');
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 32', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

pkgs = [
    {'reference':'jasper-2.0.24-1.fc32', 'release':'FC32', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jasper');
}
