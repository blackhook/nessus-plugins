#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1236-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153108);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-0089",
    "CVE-2021-28690",
    "CVE-2021-28692",
    "CVE-2021-28693",
    "CVE-2021-28694",
    "CVE-2021-28695",
    "CVE-2021-28696",
    "CVE-2021-28697",
    "CVE-2021-28698",
    "CVE-2021-28699",
    "CVE-2021-28700"
  );
  script_xref(name:"IAVB", value:"2021-B-0044-S");
  script_xref(name:"IAVB", value:"2021-B-0060-S");

  script_name(english:"openSUSE 15 Security Update : xen (openSUSE-SU-2021:1236-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1236-1 advisory.

  - Observable response discrepancy in some Intel(R) Processors may allow an authorized user to potentially
    enable information disclosure via local access. (CVE-2021-0089)

  - x86: TSX Async Abort protections not restored after S3 This issue relates to the TSX Async Abort
    speculative security vulnerability. Please see https://xenbits.xen.org/xsa/advisory-305.html for details.
    Mitigating TAA by disabling TSX (the default and preferred option) requires selecting a non-default
    setting in MSR_TSX_CTRL. This setting isn't restored after S3 suspend. (CVE-2021-28690)

  - inappropriate x86 IOMMU timeout detection / handling IOMMUs process commands issued to them in parallel
    with the operation of the CPU(s) issuing such commands. In the current implementation in Xen, asynchronous
    notification of the completion of such commands is not used. Instead, the issuing CPU spin-waits for the
    completion of the most recently issued command(s). Some of these waiting loops try to apply a timeout to
    fail overly-slow commands. The course of action upon a perceived timeout actually being detected is
    inappropriate: - on Intel hardware guests which did not originally cause the timeout may be marked as
    crashed, - on AMD hardware higher layer callers would not be notified of the issue, making them continue
    as if the IOMMU operation succeeded. (CVE-2021-28692)

  - xen/arm: Boot modules are not scrubbed The bootloader will load boot modules (e.g. kernel, initramfs...)
    in a temporary area before they are copied by Xen to each domain memory. To ensure sensitive data is not
    leaked from the modules, Xen must scrub them before handing the page over to the allocator.
    Unfortunately, it was discovered that modules will not be scrubbed on Arm. (CVE-2021-28693)

  - IOMMU page mapping issues on x86 T[his CNA information record relates to multiple CVEs; the text explains
    which aspects/vulnerabilities correspond to which CVE.] Both AMD and Intel allow ACPI tables to specify
    regions of memory which should be left untranslated, which typically means these addresses should pass the
    translation phase unaltered. While these are typically device specific ACPI properties, they can also be
    specified to apply to a range of devices, or even all devices. On all systems with such regions Xen failed
    to prevent guests from undoing/replacing such mappings (CVE-2021-28694). On AMD systems, where a
    discontinuous range is specified by firmware, the supposedly-excluded middle range will also be identity-
    mapped (CVE-2021-28695). Further, on AMD systems, upon de-assigment of a physical device from a guest, the
    identity mappings would be left in place, allowing a guest continued access to ranges of memory which it
    shouldn't have access to anymore (CVE-2021-28696). (CVE-2021-28694, CVE-2021-28695, CVE-2021-28696)

  - grant table v2 status pages may remain accessible after de-allocation Guest get permitted access to
    certain Xen-owned pages of memory. The majority of such pages remain allocated / associated with a guest
    for its entire lifetime. Grant table v2 status pages, however, get de-allocated when a guest switched
    (back) from v2 to v1. The freeing of such pages requires that the hypervisor know where in the guest these
    pages were mapped. The hypervisor tracks only one use within guest space, but racing requests from the
    guest to insert mappings of these pages may result in any of them to become mapped in multiple locations.
    Upon switching back from v2 to v1, the guest would then retain access to a page that was freed and perhaps
    re-used for other purposes. (CVE-2021-28697)

  - long running loops in grant table handling In order to properly monitor resource use, Xen maintains
    information on the grant mappings a domain may create to map grants offered by other domains. In the
    process of carrying out certain actions, Xen would iterate over all such entries, including ones which
    aren't in use anymore and some which may have been created but never used. If the number of entries for a
    given domain is large enough, this iterating of the entire table may tie up a CPU for too long, starving
    other domains or causing issues in the hypervisor itself. Note that a domain may map its own grants, i.e.
    there is no need for multiple domains to be involved here. A pair of cooperating guests may, however,
    cause the effects to be more severe. (CVE-2021-28698)

  - inadequate grant-v2 status frames array bounds check The v2 grant table interface separates grant
    attributes from grant status. That is, when operating in this mode, a guest has two tables. As a result,
    guests also need to be able to retrieve the addresses that the new status tracking table can be accessed
    through. For 32-bit guests on x86, translation of requests has to occur because the interface structure
    layouts commonly differ between 32- and 64-bit. The translation of the request to obtain the frame numbers
    of the grant status table involves translating the resulting array of frame numbers. Since the space used
    to carry out the translation is limited, the translation layer tells the core function the capacity of the
    array within translation space. Unfortunately the core function then only enforces array bounds to be
    below 8 times the specified value, and would write past the available space if enough frame numbers needed
    storing. (CVE-2021-28699)

  - xen/arm: No memory limit for dom0less domUs The dom0less feature allows an administrator to create
    multiple unprivileged domains directly from Xen. Unfortunately, the memory limit from them is not set.
    This allow a domain to allocate memory beyond what an administrator originally configured.
    (CVE-2021-28700)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1027519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1137251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189882");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VYJVCSKTOQY75TLGWH3HDYZAS33JTOTQ/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27e534b8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28700");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28692");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-xendomains-wait-disk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'xen-4.13.3_02-lp152.2.27.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-devel-4.13.3_02-lp152.2.27.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-libs-32bit-4.13.3_02-lp152.2.27.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-libs-4.13.3_02-lp152.2.27.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-tools-4.13.3_02-lp152.2.27.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-tools-domU-4.13.3_02-lp152.2.27.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-tools-xendomains-wait-disk-4.13.3_02-lp152.2.27.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-devel / xen-libs / xen-libs-32bit / xen-tools / etc');
}
