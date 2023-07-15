##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9595.
##

include('compat.inc');

if (description)
{
  script_id(163114);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-3695",
    "CVE-2021-3696",
    "CVE-2021-3697",
    "CVE-2022-28733",
    "CVE-2022-28734",
    "CVE-2022-28735",
    "CVE-2022-28736",
    "CVE-2022-28737"
  );

  script_name(english:"Oracle Linux 8 : grub2 (ELSA-2022-9595)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-9595 advisory.

  - shim: Buffer overflow when loading crafted EFI images (CVE-2022-28737)

  - A heap out-of-bounds write may heppen during the handling of Huffman tables in the PNG reader. This may
    lead to data corruption in the heap space. Confidentiality, Integrity and Availablity impact may be
    considered Low as it's very complex to an attacker control the encoding and positioning of corrupted
    Huffman entries to achieve results such as arbitrary code execution and/or secure boot circumvention. This
    flaw affects grub2 versions prior grub-2.12. (CVE-2021-3696)

  - grub2: Out-of-bound write when handling split HTTP headers (CVE-2022-28734)

  - A crafted 16-bit grayscale PNG image may lead to a out-of-bounds write in the heap area. An attacker may
    take advantage of that to cause heap data corruption or eventually arbitrary code execution and circumvent
    secure boot protections. This issue has a high complexity to be exploited as an attacker needs to perform
    some triage over the heap layout to achieve signifcant results, also the values written into the memory
    are repeated three times in a row making difficult to produce valid payloads. This flaw affects grub2
    versions prior grub-2.12. (CVE-2021-3695)

  - A crafted JPEG image may lead the JPEG reader to underflow its data pointer, allowing user-controlled data
    to be written in heap. To a successful to be performed the attacker needs to perform some triage over the
    heap layout and craft an image with a malicious format and payload. This vulnerability can lead to data
    corruption and eventual code execution or secure boot circumvention. This flaw affects grub2 versions
    prior grub-2.12. (CVE-2021-3697)

  - grub2: Integer underflow in grub_net_recv_ip4_packets (CVE-2022-28733)

  - grub2: shim_lock verifier allows non-kernel files to be loaded (CVE-2022-28735)

  - grub2: use-after-free in grub_cmd_chainloader() (CVE-2022-28736)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9595.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-aa64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-ia32-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-tools-minimal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'grub2-common-2.02-123.0.7.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-aa64-2.02-123.0.7.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-aa64-cdboot-2.02-123.0.7.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-aa64-modules-2.02-123.0.7.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-ia32-2.02-123.0.7.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-ia32-cdboot-2.02-123.0.7.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-ia32-modules-2.02-123.0.7.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-x64-2.02-123.0.7.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-x64-cdboot-2.02-123.0.7.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-x64-modules-2.02-123.0.7.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-pc-2.02-123.0.7.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-pc-modules-2.02-123.0.7.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-2.02-123.0.7.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-2.02-123.0.7.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-efi-2.02-123.0.7.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-extra-2.02-123.0.7.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-extra-2.02-123.0.7.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-minimal-2.02-123.0.7.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-minimal-2.02-123.0.7.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2-common / grub2-efi-aa64 / grub2-efi-aa64-cdboot / etc');
}
