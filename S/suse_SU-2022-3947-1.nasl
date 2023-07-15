#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3947-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167351);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-33746",
    "CVE-2022-33747",
    "CVE-2022-33748",
    "CVE-2022-42309",
    "CVE-2022-42310",
    "CVE-2022-42311",
    "CVE-2022-42312",
    "CVE-2022-42313",
    "CVE-2022-42314",
    "CVE-2022-42315",
    "CVE-2022-42316",
    "CVE-2022-42317",
    "CVE-2022-42318",
    "CVE-2022-42319",
    "CVE-2022-42320",
    "CVE-2022-42321",
    "CVE-2022-42322",
    "CVE-2022-42323",
    "CVE-2022-42325",
    "CVE-2022-42326"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3947-1");
  script_xref(name:"IAVB", value:"2022-B-0048");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : xen (SUSE-SU-2022:3947-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3947-1 advisory.

  - P2M pool freeing may take excessively long The P2M pool backing second level address translation for
    guests may be of significant size. Therefore its freeing may take more time than is reasonable without
    intermediate preemption checks. Such checking for the need to preempt was so far missing. (CVE-2022-33746)

  - Arm: unbounded memory consumption for 2nd-level page tables Certain actions require e.g. removing pages
    from a guest's P2M (Physical-to-Machine) mapping. When large pages are in use to map guest pages in the
    2nd-stage page tables, such a removal operation may incur a memory allocation (to replace a large mapping
    with individual smaller ones). These memory allocations are taken from the global memory pool. A malicious
    guest might be able to cause the global memory pool to be exhausted by manipulating its own P2M mappings.
    (CVE-2022-33747)

  - lock order inversion in transitive grant copy handling As part of XSA-226 a missing cleanup call was
    inserted on an error handling path. While doing so, locking requirements were not paid attention to. As a
    result two cooperating guests granting each other transitive grants can cause locks to be acquired nested
    within one another, but in respectively opposite order. With suitable timing between the involved grant
    copy operations this may result in the locking up of a CPU. (CVE-2022-33748)

  - Xenstore: Guests can crash xenstored Due to a bug in the fix of XSA-115 a malicious guest can cause
    xenstored to use a wrong pointer during node creation in an error path, resulting in a crash of xenstored
    or a memory corruption in xenstored causing further damage. Entering the error path can be controlled by
    the guest e.g. by exceeding the quota value of maximum nodes per domain. (CVE-2022-42309)

  - Xenstore: Guests can create orphaned Xenstore nodes By creating multiple nodes inside a transaction
    resulting in an error, a malicious guest can create orphaned nodes in the Xenstore data base, as the
    cleanup after the error will not remove all nodes already created. When the transaction is committed after
    this situation, nodes without a valid parent can be made permanent in the data base. (CVE-2022-42310)

  - Xenstore: guests can let run xenstored out of memory T[his CNA information record relates to multiple
    CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Malicious guests can cause
    xenstored to allocate vast amounts of memory, eventually resulting in a Denial of Service (DoS) of
    xenstored. There are multiple ways how guests can cause large memory allocations in xenstored: - - by
    issuing new requests to xenstored without reading the responses, causing the responses to be buffered in
    memory - - by causing large number of watch events to be generated via setting up multiple xenstore
    watches and then e.g. deleting many xenstore nodes below the watched path - - by creating as many nodes as
    allowed with the maximum allowed size and path length in as many transactions as possible - - by accessing
    many nodes inside a transaction (CVE-2022-42311, CVE-2022-42312, CVE-2022-42313, CVE-2022-42314,
    CVE-2022-42315, CVE-2022-42316, CVE-2022-42317, CVE-2022-42318)

  - Xenstore: Guests can cause Xenstore to not free temporary memory When working on a request of a guest,
    xenstored might need to allocate quite large amounts of memory temporarily. This memory is freed only
    after the request has been finished completely. A request is regarded to be finished only after the guest
    has read the response message of the request from the ring page. Thus a guest not reading the response can
    cause xenstored to not free the temporary memory. This can result in memory shortages causing Denial of
    Service (DoS) of xenstored. (CVE-2022-42319)

  - Xenstore: Guests can get access to Xenstore nodes of deleted domains Access rights of Xenstore nodes are
    per domid. When a domain is gone, there might be Xenstore nodes left with access rights containing the
    domid of the removed domain. This is normally no problem, as those access right entries will be corrected
    when such a node is written later. There is a small time window when a new domain is created, where the
    access rights of a past domain with the same domid as the new one will be regarded to be still valid,
    leading to the new domain being able to get access to a node which was meant to be accessible by the
    removed domain. For this to happen another domain needs to write the node before the newly created domain
    is being introduced to Xenstore by dom0. (CVE-2022-42320)

  - Xenstore: Guests can crash xenstored via exhausting the stack Xenstored is using recursion for some
    Xenstore operations (e.g. for deleting a sub-tree of Xenstore nodes). With sufficiently deep nesting
    levels this can result in stack exhaustion on xenstored, leading to a crash of xenstored. (CVE-2022-42321)

  - Xenstore: Cooperating guests can create arbitrary numbers of nodes T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Since the fix of
    XSA-322 any Xenstore node owned by a removed domain will be modified to be owned by Dom0. This will allow
    two malicious guests working together to create an arbitrary number of Xenstore nodes. This is possible by
    domain A letting domain B write into domain A's local Xenstore tree. Domain B can then create many nodes
    and reboot. The nodes created by domain B will now be owned by Dom0. By repeating this process over and
    over again an arbitrary number of nodes can be created, as Dom0's number of nodes isn't limited by
    Xenstore quota. (CVE-2022-42322, CVE-2022-42323)

  - Xenstore: Guests can create arbitrary number of nodes via transactions T[his CNA information record
    relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] In
    case a node has been created in a transaction and it is later deleted in the same transaction, the
    transaction will be terminated with an error. As this error is encountered only when handling the deleted
    node at transaction finalization, the transaction will have been performed partially and without updating
    the accounting information. This will enable a malicious guest to create arbitrary number of nodes.
    (CVE-2022-42325, CVE-2022-42326)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1027519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204496");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/012906.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfff732b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42309");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42311");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42314");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42315");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42316");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42317");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42323");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42325");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42326");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-xendomains-wait-disk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'xen-4.14.5_08-150300.3.40.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'xen-devel-4.14.5_08-150300.3.40.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'xen-libs-4.14.5_08-150300.3.40.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'xen-libs-4.14.5_08-150300.3.40.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'xen-tools-4.14.5_08-150300.3.40.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'xen-tools-domU-4.14.5_08-150300.3.40.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'xen-tools-domU-4.14.5_08-150300.3.40.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'xen-tools-xendomains-wait-disk-4.14.5_08-150300.3.40.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'xen-4.14.5_08-150300.3.40.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-4.14.5_08-150300.3.40.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-devel-4.14.5_08-150300.3.40.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-devel-4.14.5_08-150300.3.40.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-doc-html-4.14.5_08-150300.3.40.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-doc-html-4.14.5_08-150300.3.40.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-libs-32bit-4.14.5_08-150300.3.40.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-libs-4.14.5_08-150300.3.40.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-libs-4.14.5_08-150300.3.40.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-tools-4.14.5_08-150300.3.40.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-tools-4.14.5_08-150300.3.40.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-tools-domU-4.14.5_08-150300.3.40.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-tools-domU-4.14.5_08-150300.3.40.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'xen-tools-xendomains-wait-disk-4.14.5_08-150300.3.40.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-devel / xen-doc-html / xen-libs / xen-libs-32bit / xen-tools / etc');
}
