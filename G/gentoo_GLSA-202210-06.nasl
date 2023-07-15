#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-06.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166166);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/16");

  script_cve_id(
    "CVE-2020-14339",
    "CVE-2020-25637",
    "CVE-2021-3631",
    "CVE-2021-3667",
    "CVE-2022-0897"
  );

  script_name(english:"GLSA-202210-06 : libvirt: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-06 (libvirt: Multiple Vulnerabilities)

  - A flaw was found in libvirt, where it leaked a file descriptor for `/dev/mapper/control` into the QEMU
    process. This file descriptor allows for privileged operations to happen against the device-mapper on the
    host. This flaw allows a malicious guest user or process to perform operations outside of their standard
    permissions, potentially causing serious damage to the host operating system. The highest threat from this
    vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2020-14339)

  - A double free memory issue was found to occur in the libvirt API, in versions before 6.8.0, responsible
    for requesting information about network interfaces of a running QEMU domain. This flaw affects the polkit
    access control driver. Specifically, clients connecting to the read-write socket with limited ACL
    permissions could use this flaw to crash the libvirt daemon, resulting in a denial of service, or
    potentially escalate their privileges on the system. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25637)

  - A flaw was found in libvirt while it generates SELinux MCS category pairs for VMs' dynamic labels. This
    flaw allows one exploited guest to access files labeled for another guest, resulting in the breaking out
    of sVirt confinement. The highest threat from this vulnerability is to confidentiality and integrity.
    (CVE-2021-3631)

  - An improper locking issue was found in the virStoragePoolLookupByTargetPath API of libvirt. It occurs in
    the storagePoolLookupByTargetPath function where a locked virStoragePoolObj object is not properly
    released on ACL permission failure. Clients connecting to the read-write socket with limited ACL
    permissions could use this flaw to acquire the lock and prevent other users from accessing storage
    pool/volume APIs, resulting in a denial of service condition. The highest threat from this vulnerability
    is to system availability. (CVE-2021-3667)

  - A flaw was found in the libvirt nwfilter driver. The virNWFilterObjListNumOfNWFilters method failed to
    acquire the driver->nwfilters mutex before iterating over virNWFilterObj instances. There was no
    protection to stop another thread from concurrently modifying the driver->nwfilters object. This flaw
    allows a malicious, unprivileged user to exploit this issue via libvirt's API virConnectNumOfNWFilters to
    crash the network filter management daemon (libvirtd/virtnwfilterd). (CVE-2022-0897)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-06");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=746119");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=799713");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=812317");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836128");
  script_set_attribute(attribute:"solution", value:
"All libvirt users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-emulation/libvirt-8.2.0
        
All libvirt-python users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-python/libvirt-python-8.2.0");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libvirt-python");
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
    'name' : "app-emulation/libvirt",
    'unaffected' : make_list("ge 8.2.0", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.2.0")
  },
  {
    'name' : "dev-python/libvirt-python",
    'unaffected' : make_list("ge 8.2.0", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.2.0")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

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
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
