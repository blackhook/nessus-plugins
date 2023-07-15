#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-e63bc3eca2
#

include('compat.inc');

if (description)
{
  script_id(169432);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/31");

  script_cve_id(
    "CVE-2022-4198",
    "CVE-2022-4199",
    "CVE-2022-36354",
    "CVE-2022-38143",
    "CVE-2022-41639",
    "CVE-2022-41684",
    "CVE-2022-41794",
    "CVE-2022-41838",
    "CVE-2022-41977",
    "CVE-2022-41988",
    "CVE-2022-41999"
  );
  script_xref(name:"FEDORA", value:"2022-e63bc3eca2");

  script_name(english:"Fedora 36 : OpenImageIO (2022-e63bc3eca2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-e63bc3eca2 advisory.

  - A heap out-of-bounds read vulnerability exists in the RLA format parser of OpenImageIO master-
    branch-9aeece7a and v2.3.19.0. More specifically, in the way run-length encoded byte spans are handled. A
    malformed RLA file can lead to an out-of-bounds read of heap metadata which can result in sensitive
    information leak. An attacker can provide a malicious file to trigger this vulnerability. (CVE-2022-36354)

  - A heap out-of-bounds write vulnerability exists in the way OpenImageIO v2.3.19.0 processes RLE encoded BMP
    images. A specially-crafted bmp file can write to arbitrary out of bounds memory, which can lead to
    arbitrary code execution. An attacker can provide a malicious file to trigger this vulnerability.
    (CVE-2022-38143)

  - A heap based buffer overflow vulnerability exists in tile decoding code of TIFF image parser in
    OpenImageIO master-branch-9aeece7a and v2.3.19.0. A specially-crafted TIFF file can lead to an out of
    bounds memory corruption, which can result in arbitrary code execution. An attacker can provide a
    malicious file to trigger this vulnerability. (CVE-2022-41639)

  - A heap out of bounds read vulnerability exists in the OpenImageIO master-branch-9aeece7a when parsing the
    image file directory part of a PSD image file. A specially-crafted .psd file can cause a read of arbitrary
    memory address which can lead to denial of service. An attacker can provide a malicious file to trigger
    this vulnerability. (CVE-2022-41684)

  - A heap based buffer overflow vulnerability exists in the PSD thumbnail resource parsing code of
    OpenImageIO 2.3.19.0. A specially-crafted PSD file can lead to arbitrary code execution. An attacker can
    provide a malicious file to trigger this vulnerability. (CVE-2022-41794)

  - A code execution vulnerability exists in the DDS scanline parsing functionality of OpenImageIO Project
    OpenImageIO v2.4.4.2. A specially-crafted .dds can lead to a heap buffer overflow. An attacker can provide
    a malicious file to trigger this vulnerability. (CVE-2022-41838)

  - An out of bounds read vulnerability exists in the way OpenImageIO version v2.3.19.0 processes string
    fields in TIFF image files. A specially-crafted TIFF file can lead to information disclosure. An attacker
    can provide a malicious file to trigger this vulnerability. (CVE-2022-41977)

  - An information disclosure vulnerability exists in the OpenImageIO::decode_iptc_iim() functionality of
    OpenImageIO Project OpenImageIO v2.3.19.0. A specially-crafted TIFF file can lead to a disclosure of
    sensitive information. An attacker can provide a malicious file to trigger this vulnerability.
    (CVE-2022-41988)

  - A denial of service vulnerability exists in the DDS native tile reading functionality of OpenImageIO
    Project OpenImageIO v2.3.19.0 and v2.4.4.2. A specially-crafted .dds can lead to denial of service. An
    attacker can provide a malicious file to trigger this vulnerability. (CVE-2022-41999)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-e63bc3eca2");
  script_set_attribute(attribute:"solution", value:
"Update the affected OpenImageIO package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41838");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:OpenImageIO");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'OpenImageIO-2.3.21.0-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'OpenImageIO');
}
