#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202301-01.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(169841);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id(
    "CVE-2021-33285",
    "CVE-2021-33286",
    "CVE-2021-33287",
    "CVE-2021-33289",
    "CVE-2021-35266",
    "CVE-2021-35267",
    "CVE-2021-35268",
    "CVE-2021-35269",
    "CVE-2021-39251",
    "CVE-2021-39252",
    "CVE-2021-39253",
    "CVE-2021-39254",
    "CVE-2021-39255",
    "CVE-2021-39256",
    "CVE-2021-39257",
    "CVE-2021-39258",
    "CVE-2021-39259",
    "CVE-2021-39260",
    "CVE-2021-39261",
    "CVE-2021-39262",
    "CVE-2021-39263",
    "CVE-2022-30783",
    "CVE-2022-30784",
    "CVE-2022-30785",
    "CVE-2022-30786",
    "CVE-2022-30787",
    "CVE-2022-30788",
    "CVE-2022-30789",
    "CVE-2022-40284"
  );

  script_name(english:"GLSA-202301-01 : NTFS-3G: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202301-01 (NTFS-3G: Multiple Vulnerabilities)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS attribute is supplied to the function
    ntfs_get_attribute_value, a heap buffer overflow can occur allowing for memory disclosure or denial of
    service. The vulnerability is caused by an out-of-bound buffer access which can be triggered by mounting a
    crafted ntfs partition. The root cause is a missing consistency check after reading an MFT record : the
    bytes_in_use field should be less than the bytes_allocated field. When it is not, the parsing of the
    records proceeds into the wild. (CVE-2021-33285)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted unicode string is supplied in an NTFS image a
    heap buffer overflow can occur and allow for code execution. (CVE-2021-33286)

  - In NTFS-3G versions < 2021.8.22, when specially crafted NTFS attributes are read in the function
    ntfs_attr_pread_i, a heap buffer overflow can occur and allow for writing to arbitrary memory or denial of
    service of the application. (CVE-2021-33287)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted MFT section is supplied in an NTFS image a heap
    buffer overflow can occur and allow for code execution. (CVE-2021-33289)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode pathname is supplied in an NTFS image
    a heap buffer overflow can occur resulting in memory disclosure, denial of service and even code
    execution. (CVE-2021-35266)

  - NTFS-3G versions < 2021.8.22, a stack buffer overflow can occur when correcting differences in the MFT and
    MFTMirror allowing for code execution or escalation of privileges when setuid-root. (CVE-2021-35267)

  - In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode is loaded in the function
    ntfs_inode_real_open, a heap buffer overflow can occur allowing for code execution and escalation of
    privileges. (CVE-2021-35268)

  - NTFS-3G versions < 2021.8.22, when a specially crafted NTFS attribute from the MFT is setup in the
    function ntfs_attr_setup_flag, a heap buffer overflow can occur allowing for code execution and escalation
    of privileges. (CVE-2021-35269)

  - A crafted NTFS image can cause a NULL pointer dereference in ntfs_extent_inode_open in NTFS-3G <
    2021.8.22. (CVE-2021-39251)

  - A crafted NTFS image can cause an out-of-bounds read in ntfs_ie_lookup in NTFS-3G < 2021.8.22.
    (CVE-2021-39252)

  - A crafted NTFS image can cause an out-of-bounds read in ntfs_runlists_merge_i in NTFS-3G < 2021.8.22.
    (CVE-2021-39253)

  - A crafted NTFS image can cause an integer overflow in memmove, leading to a heap-based buffer overflow in
    the function ntfs_attr_record_resize, in NTFS-3G < 2021.8.22. (CVE-2021-39254)

  - A crafted NTFS image can trigger an out-of-bounds read, caused by an invalid attribute in
    ntfs_attr_find_in_attrdef, in NTFS-3G < 2021.8.22. (CVE-2021-39255)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_inode_lookup_by_name in NTFS-3G <
    2021.8.22. (CVE-2021-39256)

  - A crafted NTFS image with an unallocated bitmap can lead to a endless recursive function call chain
    (starting from ntfs_attr_pwrite), causing stack consumption in NTFS-3G < 2021.8.22. (CVE-2021-39257)

  - A crafted NTFS image can cause out-of-bounds reads in ntfs_attr_find and ntfs_external_attr_find in
    NTFS-3G < 2021.8.22. (CVE-2021-39258)

  - A crafted NTFS image can trigger an out-of-bounds access, caused by an unsanitized attribute length in
    ntfs_inode_lookup_by_name, in NTFS-3G < 2021.8.22. (CVE-2021-39259)

  - A crafted NTFS image can cause an out-of-bounds access in ntfs_inode_sync_standard_information in NTFS-3G
    < 2021.8.22. (CVE-2021-39260)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_compressed_pwrite in NTFS-3G <
    2021.8.22. (CVE-2021-39261)

  - A crafted NTFS image can cause an out-of-bounds access in ntfs_decompress in NTFS-3G < 2021.8.22.
    (CVE-2021-39262)

  - A crafted NTFS image can trigger a heap-based buffer overflow, caused by an unsanitized attribute in
    ntfs_get_attribute_value, in NTFS-3G < 2021.8.22. (CVE-2021-39263)

  - An invalid return code in fuse_kern_mount enables intercepting of libfuse-lite protocol traffic between
    NTFS-3G and the kernel in NTFS-3G through 2021.8.22 when using libfuse-lite. (CVE-2022-30783)

  - A crafted NTFS image can cause heap exhaustion in ntfs_get_attribute_value in NTFS-3G through 2021.8.22.
    (CVE-2022-30784)

  - A file handle created in fuse_lib_opendir, and later used in fuse_lib_readdir, enables arbitrary memory
    read and write operations in NTFS-3G through 2021.8.22 when using libfuse-lite. (CVE-2022-30785)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_names_full_collate in NTFS-3G through
    2021.8.22. (CVE-2022-30786)

  - An integer underflow in fuse_lib_readdir enables arbitrary memory read operations in NTFS-3G through
    2021.8.22 when using libfuse-lite. (CVE-2022-30787)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_mft_rec_alloc in NTFS-3G through
    2021.8.22. (CVE-2022-30788)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_check_log_client_array in NTFS-3G
    through 2021.8.22. (CVE-2022-30789)

  - A buffer overflow was discovered in NTFS-3G before 2022.10.3. Crafted metadata in an NTFS image can cause
    code execution. A local attacker can exploit this if the ntfs-3g binary is setuid root. A physically
    proximate attacker can exploit this if NTFS-3G software is configured to execute upon attachment of an
    external storage device. (CVE-2022-40284)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202301-01");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=811156");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=847598");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=878885");
  script_set_attribute(attribute:"solution", value:
"All NTFS-3G users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=sys-fs/ntfs3g-2022.10.3");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-40284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ntfs3g");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'sys-fs/ntfs3g',
    'unaffected' : make_list("ge 2022.10.3"),
    'vulnerable' : make_list("lt 2022.10.3")
  }
];

foreach var package( packages ) {
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
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'NTFS-3G');
}
