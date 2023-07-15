#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-07438e12df
#

include('compat.inc');

if (description)
{
  script_id(169223);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/23");

  script_cve_id(
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
    "CVE-2022-42326",
    "CVE-2022-42327"
  );
  script_xref(name:"IAVB", value:"2022-B-0048");
  script_xref(name:"FEDORA", value:"2022-07438e12df");

  script_name(english:"Fedora 36 : xen (2022-07438e12df)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-07438e12df advisory.

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

  - x86: unintended memory sharing between guests On Intel systems that support the virtualize APIC accesses
    feature, a guest can read and write the global shared xAPIC page by moving the local APIC out of xAPIC
    mode. Access to this shared page bypasses the expected isolation that should exist between two guests.
    (CVE-2022-42327)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-07438e12df");
  script_set_attribute(attribute:"solution", value:
"Update the affected xen package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'xen-4.16.2-3.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen');
}
