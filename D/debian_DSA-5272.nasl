#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5272. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(167052);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/24");

  script_cve_id(
    "CVE-2022-33745",
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
    "CVE-2022-42324",
    "CVE-2022-42325",
    "CVE-2022-42326"
  );
  script_xref(name:"IAVB", value:"2022-B-0048");

  script_name(english:"Debian DSA-5272-1 : xen - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5272 advisory.

  - insufficient TLB flush for x86 PV guests in shadow mode For migration as well as to work around kernels
    unaware of L1TF (see XSA-273), PV guests may be run in shadow paging mode. To address XSA-401, code was
    moved inside a function in Xen. This code movement missed a variable changing meaning / value between old
    and new code positions. The now wrong use of the variable did lead to a wrong TLB flush condition,
    omitting flushes where such are necessary. (CVE-2022-33745)

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

  - Oxenstored 32->31 bit integer truncation issues Integers in Ocaml are 63 or 31 bits of signed precision.
    The Ocaml Xenbus library takes a C uint32_t out of the ring and casts it directly to an Ocaml integer. In
    64-bit Ocaml builds this is fine, but in 32-bit builds, it truncates off the most significant bit, and
    then creates unsigned/signed confusion in the remainder. This in turn can feed a negative value into logic
    not expecting a negative value, resulting in unexpected exceptions being thrown. The unexpected exception
    is not handled suitably, creating a busy-loop trying (and failing) to take the bad packet out of the
    xenstore ring. (CVE-2022-42324)

  - Xenstore: Guests can create arbitrary number of nodes via transactions T[his CNA information record
    relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] In
    case a node has been created in a transaction and it is later deleted in the same transaction, the
    transaction will be terminated with an error. As this error is encountered only when handling the deleted
    node at transaction finalization, the transaction will have been performed partially and without updating
    the accounting information. This will enable a malicious guest to create arbitrary number of nodes.
    (CVE-2022-42325, CVE-2022-42326)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xen");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5272");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33746");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33747");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42309");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42310");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42311");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42312");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42313");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42314");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42315");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42316");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42317");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42318");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42319");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42320");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42321");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42322");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42323");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42324");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42325");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42326");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/xen");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xen packages.

For the stable distribution (bullseye), these problems have been fixed in version 4.14.5+86-g1c354767d5-1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33745");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxencall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxendevicemodel1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenevtchn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenforeignmemory1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxengnttab1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenhypfs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenmisc4.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenstore3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxentoolcore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxentoollog1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.14-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.14-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.14-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-4.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xenstore-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libxen-dev', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxencall1', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxendevicemodel1', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxenevtchn1', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxenforeignmemory1', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxengnttab1', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxenhypfs1', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxenmisc4.14', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxenstore3.0', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxentoolcore1', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'libxentoollog1', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-doc', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-amd64', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-arm64', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-4.14-armhf', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-hypervisor-common', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-system-amd64', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-system-arm64', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-system-armhf', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-utils-4.14', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xen-utils-common', 'reference': '4.14.5+86-g1c354767d5-1'},
    {'release': '11.0', 'prefix': 'xenstore-utils', 'reference': '4.14.5+86-g1c354767d5-1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxen-dev / libxencall1 / libxendevicemodel1 / libxenevtchn1 / etc');
}
