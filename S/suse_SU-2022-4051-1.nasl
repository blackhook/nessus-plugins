#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4051-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167932);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2021-28689",
    "CVE-2022-33746",
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
    "CVE-2022-42320",
    "CVE-2022-42321",
    "CVE-2022-42322",
    "CVE-2022-42323"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4051-1");
  script_xref(name:"IAVB", value:"2021-B-0011-S");
  script_xref(name:"IAVB", value:"2022-B-0048");

  script_name(english:"SUSE SLES12 Security Update : xen (SUSE-SU-2022:4051-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:4051-1 advisory.

  - x86: Speculative vulnerabilities with bare (non-shim) 32-bit PV guests 32-bit x86 PV guest kernels run in
    ring 1. At the time when Xen was developed, this area of the i386 architecture was rarely used, which is
    why Xen was able to use it to implement paravirtualisation, Xen's novel approach to virtualization. In
    AMD64, Xen had to use a different implementation approach, so Xen does not use ring 1 to support 64-bit
    guests. With the focus now being on 64-bit systems, and the availability of explicit hardware support for
    virtualization, fixing speculation issues in ring 1 is not a priority for processor companies. Indirect
    Branch Restricted Speculation (IBRS) is an architectural x86 extension put together to combat speculative
    execution sidechannel attacks, including Spectre v2. It was retrofitted in microcode to existing CPUs. For
    more details on Spectre v2, see: http://xenbits.xen.org/xsa/advisory-254.html However, IBRS does not
    architecturally protect ring 0 from predictions learnt in ring 1. For more details, see:
    https://software.intel.com/security-software-guidance/deep-dives/deep-dive-indirect-branch-restricted-
    speculation Similar situations may exist with other mitigations for other kinds of speculative execution
    attacks. The situation is quite likely to be similar for speculative execution attacks which have yet to
    be discovered, disclosed, or mitigated. (CVE-2021-28689)

  - P2M pool freeing may take excessively long The P2M pool backing second level address translation for
    guests may be of significant size. Therefore its freeing may take more time than is reasonable without
    intermediate preemption checks. Such checking for the need to preempt was so far missing. (CVE-2022-33746)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204494");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/012964.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c4ff613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33746");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42323");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28689");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'xen-4.7.6_28-43.98.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'xen-doc-html-4.7.6_28-43.98.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'xen-libs-32bit-4.7.6_28-43.98.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'xen-libs-4.7.6_28-43.98.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'xen-tools-4.7.6_28-43.98.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'xen-tools-domU-4.7.6_28-43.98.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-doc-html / xen-libs / xen-libs-32bit / xen-tools / etc');
}
