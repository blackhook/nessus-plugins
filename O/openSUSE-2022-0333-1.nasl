#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0333-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157400);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/05");

  script_cve_id("CVE-2022-23033", "CVE-2022-23034", "CVE-2022-23035");

  script_name(english:"openSUSE 15 Security Update : xen (openSUSE-SU-2022:0333-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0333-1 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194588");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XIM2A32O55DKEA5CCA7L5EE2KL4DYQJF/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c718f4ab");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23035");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23033");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-xendomains-wait-disk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'xen-4.14.3_06-150300.3.18.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-4.14.3_06-150300.3.18.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-devel-4.14.3_06-150300.3.18.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-devel-4.14.3_06-150300.3.18.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-libs-32bit-4.14.3_06-150300.3.18.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-libs-4.14.3_06-150300.3.18.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-libs-4.14.3_06-150300.3.18.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-tools-4.14.3_06-150300.3.18.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-tools-4.14.3_06-150300.3.18.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-tools-domU-4.14.3_06-150300.3.18.2', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-tools-domU-4.14.3_06-150300.3.18.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xen-tools-xendomains-wait-disk-4.14.3_06-150300.3.18.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
