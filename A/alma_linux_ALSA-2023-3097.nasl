#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:3097.
##

include('compat.inc');

if (description)
{
  script_id(176127);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id(
    "CVE-2023-25563",
    "CVE-2023-25564",
    "CVE-2023-25565",
    "CVE-2023-25566",
    "CVE-2023-25567"
  );
  script_xref(name:"ALSA", value:"2023:3097");

  script_name(english:"AlmaLinux 8 : gssntlmssp (ALSA-2023:3097)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ALSA-2023:3097 advisory.

  - GSS-NTLMSSP is a mechglue plugin for the GSSAPI library that implements NTLM authentication. Prior to
    version 1.2.0, multiple out-of-bounds reads when decoding NTLM fields can trigger a denial of service. A
    32-bit integer overflow condition can lead to incorrect checks of consistency of length of internal
    buffers. Although most applications will error out before accepting a singe input buffer of 4GB in length
    this could theoretically happen. This vulnerability can be triggered via the main `gss_accept_sec_context`
    entry point if the application allows tokens greater than 4GB in length. This can lead to a large, up to
    65KB, out-of-bounds read which could cause a denial-of-service if it reads from unmapped memory. Version
    1.2.0 contains a patch for the out-of-bounds reads. (CVE-2023-25563)

  - GSS-NTLMSSP is a mechglue plugin for the GSSAPI library that implements NTLM authentication. Prior to
    version 1.2.0, memory corruption can be triggered when decoding UTF16 strings. The variable `outlen` was
    not initialized and could cause writing a zero to an arbitrary place in memory if `ntlm_str_convert()`
    were to fail, which would leave `outlen` uninitialized. This can lead to a denial of service if the write
    hits unmapped memory or randomly corrupts a byte in the application memory space. This vulnerability can
    trigger an out-of-bounds write, leading to memory corruption. This vulnerability can be triggered via the
    main `gss_accept_sec_context` entry point. This issue is fixed in version 1.2.0. (CVE-2023-25564)

  - GSS-NTLMSSP is a mechglue plugin for the GSSAPI library that implements NTLM authentication. Prior to
    version 1.2.0, an incorrect free when decoding target information can trigger a denial of service. The
    error condition incorrectly assumes the `cb` and `sh` buffers contain a copy of the data that needs to be
    freed. However, that is not the case. This vulnerability can be triggered via the main
    `gss_accept_sec_context` entry point. This will likely trigger an assertion failure in `free`, causing a
    denial-of-service. This issue is fixed in version 1.2.0. (CVE-2023-25565)

  - GSS-NTLMSSP is a mechglue plugin for the GSSAPI library that implements NTLM authentication. Prior to
    version 1.2.0, a memory leak can be triggered when parsing usernames which can trigger a denial-of-
    service. The domain portion of a username may be overridden causing an allocated memory area the size of
    the domain name to be leaked. An attacker can leak memory via the main `gss_accept_sec_context` entry
    point, potentially causing a denial-of-service. This issue is fixed in version 1.2.0. (CVE-2023-25566)

  - GSS-NTLMSSP, a mechglue plugin for the GSSAPI library that implements NTLM authentication, has an out-of-
    bounds read when decoding target information prior to version 1.2.0. The length of the `av_pair` is not
    checked properly for two of the elements which can trigger an out-of-bound read. The out-of-bounds read
    can be triggered via the main `gss_accept_sec_context` entry point and could cause a denial-of-service if
    the memory is unmapped. The issue is fixed in version 1.2.0. (CVE-2023-25567)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-3097.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected gssntlmssp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25564");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 401, 590, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gssntlmssp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'gssntlmssp-1.2.0-1.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gssntlmssp-1.2.0-1.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gssntlmssp');
}
