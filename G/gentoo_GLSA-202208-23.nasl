#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-23.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164116);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/15");

  script_cve_id(
    "CVE-2021-28694",
    "CVE-2021-28695",
    "CVE-2021-28696",
    "CVE-2021-28697",
    "CVE-2021-28698",
    "CVE-2021-28699",
    "CVE-2021-28700",
    "CVE-2021-28701",
    "CVE-2021-28702",
    "CVE-2021-28710",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-23033",
    "CVE-2022-23034",
    "CVE-2022-23035",
    "CVE-2022-26362",
    "CVE-2022-26363",
    "CVE-2022-26364"
  );

  script_name(english:"GLSA-202208-23 : Xen: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-23 (Xen: Multiple Vulnerabilities)

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

  - Another race in XENMAPSPACE_grant_table handling Guests are permitted access to certain Xen-owned pages of
    memory. The majority of such pages remain allocated / associated with a guest for its entire lifetime.
    Grant table v2 status pages, however, are de-allocated when a guest switches (back) from v2 to v1. Freeing
    such pages requires that the hypervisor enforce that no parallel request can result in the addition of a
    mapping of such a page to a guest. That enforcement was missing, allowing guests to retain access to pages
    that were freed and perhaps re-used for other purposes. Unfortunately, when XSA-379 was being prepared,
    this similar issue was not noticed. (CVE-2021-28701)

  - PCI devices with RMRRs not deassigned correctly Certain PCI devices in a system might be assigned Reserved
    Memory Regions (specified via Reserved Memory Region Reporting, RMRR). These are typically used for
    platform tasks such as legacy USB emulation. If such a device is passed through to a guest, then on guest
    shutdown the device is not properly deassigned. The IOMMU configuration for these devices which are not
    properly deassigned ends up pointing to a freed data structure, including the IO Pagetables. Subsequent
    DMA or interrupts from the device will have unpredictable behaviour, ranging from IOMMU faults to memory
    corruption. (CVE-2021-28702)

  - certain VT-d IOMMUs may not work in shared page table mode For efficiency reasons, address translation
    control structures (page tables) may (and, on suitable hardware, by default will) be shared between CPUs,
    for second-level translation (EPT), and IOMMUs. These page tables are presently set up to always be 4
    levels deep. However, an IOMMU may require the use of just 3 page table levels. In such a configuration
    the lop level table needs to be stripped before inserting the root table's address into the hardware
    pagetable base register. When sharing page tables, Xen erroneously skipped this stripping. Consequently,
    the guest is able to write to leaf page table entries. (CVE-2021-28710)

  - Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via local access. (CVE-2022-21123)

  - Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21125)

  - Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21166)

  - arm: guest_physmap_remove_page not removing the p2m mappings The functions to remove one or more entries
    from a guest p2m pagetable on Arm (p2m_remove_mapping, guest_physmap_remove_page, and p2m_set_entry with
    mfn set to INVALID_MFN) do not actually clear the pagetable entry if the entry doesn't have the valid bit
    set. It is possible to have a valid pagetable entry without the valid bit set when a guest operating
    system uses set/way cache maintenance instructions. For instance, a guest issuing a set/way cache
    maintenance instruction, then calling the XENMEM_decrease_reservation hypercall to give back memory pages
    to Xen, might be able to retain access to those pages even after Xen started reusing them for other
    purposes. (CVE-2022-23033)

  - A PV guest could DoS Xen while unmapping a grant To address XSA-380, reference counting was introduced for
    grant mappings for the case where a PV guest would have the IOMMU enabled. PV guests can request two forms
    of mappings. When both are in use for any individual mapping, unmapping of such a mapping can be requested
    in two steps. The reference count for such a mapping would then mistakenly be decremented twice. Underflow
    of the counters gets detected, resulting in the triggering of a hypervisor bug check. (CVE-2022-23034)

  - Insufficient cleanup of passed-through device IRQs The management of IRQs associated with physical devices
    exposed to x86 HVM guests involves an iterative operation in particular when cleaning up after the guest's
    use of the device. In the case where an interrupt is not quiescent yet at the time this cleanup gets
    invoked, the cleanup attempt may be scheduled to be retried. When multiple interrupts are involved, this
    scheduling of a retry may get erroneously skipped. At the same time pointers may get cleared (resulting in
    a de-reference of NULL) and freed (resulting in a use-after-free), while other code would continue to
    assume them to be valid. (CVE-2022-23035)

  - x86 pv: Race condition in typeref acquisition Xen maintains a type reference count for pages, in addition
    to a regular reference count. This scheme is used to maintain invariants required for Xen's safety, e.g.
    PV guests may not have direct writeable access to pagetables; updates need auditing by Xen. Unfortunately,
    the logic for acquiring a type reference has a race condition, whereby a safely TLB flush is issued too
    early and creates a window where the guest can re-establish the read/write mapping before writeability is
    prohibited. (CVE-2022-26362)

  - x86 pv: Insufficient care with non-coherent mappings T[his CNA information record relates to multiple
    CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen maintains a type
    reference count for pages, in addition to a regular reference count. This scheme is used to maintain
    invariants required for Xen's safety, e.g. PV guests may not have direct writeable access to pagetables;
    updates need auditing by Xen. Unfortunately, Xen's safety logic doesn't account for CPU-induced cache non-
    coherency; cases where the CPU can cause the content of the cache to be different to the content in main
    memory. In such cases, Xen's safety logic can incorrectly conclude that the contents of a page is safe.
    (CVE-2022-26363, CVE-2022-26364)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-23");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=810341");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=812485");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=816882");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=825354");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832039");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835401");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=850802");
  script_set_attribute(attribute:"solution", value:
"All Xen users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-emulation/xen-4.15.3
        
All Xen tools users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-emulation/xen-tools-4.15.3");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26364");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28710");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "app-emulation/xen",
    'unaffected' : make_list("ge 4.15.3"),
    'vulnerable' : make_list("lt 4.15.3")
  },
  {
    'name' : "app-emulation/xen-tools",
    'unaffected' : make_list("ge 4.15.3"),
    'vulnerable' : make_list("lt 4.15.3")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
