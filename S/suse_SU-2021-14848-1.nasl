#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14848-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155812);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2021-0089",
    "CVE-2021-3527",
    "CVE-2021-3592",
    "CVE-2021-3594",
    "CVE-2021-3595",
    "CVE-2021-3682",
    "CVE-2021-3930",
    "CVE-2021-20255",
    "CVE-2021-28690",
    "CVE-2021-28692",
    "CVE-2021-28697",
    "CVE-2021-28698",
    "CVE-2021-28701",
    "CVE-2021-28703",
    "CVE-2021-28705",
    "CVE-2021-28706",
    "CVE-2021-28709"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14848-1");
  script_xref(name:"IAVB", value:"2021-B-0060-S");
  script_xref(name:"IAVB", value:"2021-B-0044-S");
  script_xref(name:"IAVB", value:"2021-B-0068-S");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2021:14848-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14848-1 advisory.

  - Observable response discrepancy in some Intel(R) Processors may allow an authorized user to potentially
    enable information disclosure via local access. (CVE-2021-0089)

  - A stack overflow via an infinite recursion vulnerability was found in the eepro100 i8255x device emulator
    of QEMU. This issue occurs while processing controller commands due to a DMA reentry issue. This flaw
    allows a guest user or process to consume CPU cycles or crash the QEMU process on the host, resulting in a
    denial of service. The highest threat from this vulnerability is to system availability. (CVE-2021-20255)

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

  - Another race in XENMAPSPACE_grant_table handling Guests are permitted access to certain Xen-owned pages of
    memory. The majority of such pages remain allocated / associated with a guest for its entire lifetime.
    Grant table v2 status pages, however, are de-allocated when a guest switches (back) from v2 to v1. Freeing
    such pages requires that the hypervisor enforce that no parallel request can result in the addition of a
    mapping of such a page to a guest. That enforcement was missing, allowing guests to retain access to pages
    that were freed and perhaps re-used for other purposes. Unfortunately, when XSA-379 was being prepared,
    this similar issue was not noticed. (CVE-2021-28701)

  - The vulnerability exists due to grant table v2 status pages may remain accessible after de-allocation,
    which leads to security restrictions bypass and privilege escalation. (CVE-2021-28703)

  - issues with partially successful P2M updates on x86 T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] x86 HVM and PVH guests may be
    started in populate-on-demand (PoD) mode, to provide a way for them to later easily have more memory
    assigned. Guests are permitted to control certain P2M aspects of individual pages via hypercalls. These
    hypercalls may act on ranges of pages specified via page orders (resulting in a power-of-2 number of
    pages). In some cases the hypervisor carries out the requests by splitting them into smaller chunks. Error
    handling in certain PoD cases has been insufficient in that in particular partial success of some
    operations was not properly accounted for. There are two code paths affected - page removal
    (CVE-2021-28705) and insertion of new pages (CVE-2021-28709). (We provide one patch which combines the fix
    to both issues.) (CVE-2021-28705, CVE-2021-28709)

  - guests may exceed their designated memory limit When a guest is permitted to have close to 16TiB of
    memory, it may be able to issue hypercalls to increase its memory allocation beyond the administrator
    established limit. This is a result of a calculation done with 32-bit precision, which may overflow. It
    would then only be the overflowed (and hence small) number which gets compared against the established
    upper bound. (CVE-2021-28706)

  - A flaw was found in the USB redirector device (usb-redir) of QEMU. Small USB packets are combined into a
    single, large transfer request, to reduce the overhead and improve performance. The combined size of the
    bulk transfer is used to dynamically allocate a variable length array (VLA) on the stack without proper
    validation. Since the total size is not bounded, a malicious guest could use this flaw to influence the
    array length and cause the QEMU process to perform an excessive allocation on the stack, resulting in a
    denial of service. (CVE-2021-3527)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the bootp_input() function and could occur while processing a udp packet that is smaller than
    the size of the 'bootp_t' structure. A malicious guest could use this flaw to leak 10 bytes of
    uninitialized heap memory from the host. The highest threat from this vulnerability is to data
    confidentiality. This flaw affects libslirp versions prior to 4.6.0. (CVE-2021-3592)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the udp_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3594)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the tftp_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'tftp_t' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3595)

  - A flaw was found in the USB redirector device emulation of QEMU in versions prior to 6.1.0-rc2. It occurs
    when dropping packets during a bulk transfer from a SPICE client due to the packet queue being full. A
    malicious SPICE client could use this flaw to make QEMU call free() with faked heap chunk metadata,
    resulting in a crash of QEMU or potential code execution with the privileges of the QEMU process on the
    host. (CVE-2021-3682)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192559");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009799.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9f0be96");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20255");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28709");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3930");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28709");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
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
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'xen-4.4.4_50-61.67.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-doc-html-4.4.4_50-61.67.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_50_3.0.101_108.129-61.67.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_50_3.0.101_108.129-61.67.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-pae-4.4.4_50_3.0.101_108.129-61.67.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-32bit-4.4.4_50-61.67.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_50-61.67.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_50-61.67.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-4.4.4_50-61.67.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_50-61.67.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_50-61.67.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-doc-html / xen-kmp-default / xen-kmp-pae / xen-libs / etc');
}
