#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2971-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153117);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id(
    "CVE-2019-9755",
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
    "CVE-2021-39255",
    "CVE-2021-39256",
    "CVE-2021-39257",
    "CVE-2021-39258",
    "CVE-2021-39259",
    "CVE-2021-39260",
    "CVE-2021-39261",
    "CVE-2021-39262",
    "CVE-2021-39263"
  );

  script_name(english:"openSUSE 15 Security Update : ntfs-3g_ntfsprogs (openSUSE-SU-2021:2971-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2971-1 advisory.

  - An integer underflow issue exists in ntfs-3g 2017.3.23. A local attacker could potentially exploit this by
    running /bin/ntfs-3g with specially crafted arguments from a specially crafted directory to cause a heap
    buffer overflow, resulting in a crash or the ability to execute arbitrary code. In installations where
    /bin/ntfs-3g is a setuid-root binary, this could lead to a local escalation of privileges. (CVE-2019-9755)

  - In Tuxera ntfs-3g versions < 2021.8.22, when a specially crafted NTFS attribute is supplied to the
    function ntfs_get_attribute_value, a heap buffer overflow can occur allowing for memory disclosure or
    denial of service. The vulnerability is caused by an out-of-bound buffer access which can be triggered by
    mounting a crafted ntfs partition. The root cause is a missing consistency check after reading an MFT
    record : the bytes_in_use field should be less than the bytes_allocated field. When it is not, the
    parsing of the records proceeds into the wild. (CVE-2021-33285)

  - In Tuxera NTFS-3G versions < 2021.8.22, when a specially crafted unicode string is supplied in an NTFS
    image a heap buffer overflow can occur and allow for code execution. (CVE-2021-33286)

  - Tuxera NTFS-3G versions < 2021.8.22, when specially crafted NTFS attributes are read in the function
    ntfs_attr_pread_i, a heap buffer overflow can occur and allow for writing to arbitrary memory or denial of
    service of the application. (CVE-2021-33287)

  - In Tuxera NTFS-3G versions < 2021.8.22, when a specially crafted MFT section is supplied in an NTFS image
    a heap buffer overflow can occur and allow for code execution. (CVE-2021-33289)

  - In Tuxera NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode pathname is supplied in an
    NTFS image a heap buffer overflow can occur resulting in memory disclosure, denial of service and even
    code execution. (CVE-2021-35266)

  - In Tuxera NTFS-3G versions < 2021.8.22, a stack buffer overflow can occur when correcting differences in
    the MFT and MFTMirror allowing for code execution or escalation of privileges when setuid-root.
    (CVE-2021-35267)

  - Tuxera NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode is loaded in the function
    ntfs_inode_real_open, a heap buffer overflow can occur allowing for code execution and escalation of
    privileges. (CVE-2021-35268)

  - Tuxera NTFS-3G versions < 2021.8.22, when a specially crafted NTFS attribute from the MFT is setup in the
    function ntfs_attr_setup_flag, a heap buffer overflow can occur allowing for code execution and escalation
    of privileges. (CVE-2021-35269)

  - A crafted NTFS image can cause a NULL pointer dereference in ntfs_extent_inode_open in NTFS-3G <
    2021.8.22. (CVE-2021-39251)

  - A crafted NTFS image can cause an out-of-bounds read in ntfs_ie_lookup in NTFS-3G < 2021.8.22.
    (CVE-2021-39252)

  - A crafted NTFS image can cause an out-of-bounds read in ntfs_runlists_merge_i in NTFS-3G < 2021.8.22.
    (CVE-2021-39253)

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189720");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/APJMFOEFTZSFEAKDMRWUM25JNERJUHUT/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcd7f8db");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35266");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39251");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39253");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39255");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39256");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39257");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39258");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39260");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39262");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39263");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39263");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libntfs-3g-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libntfs-3g87");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfsprogs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libntfs-3g-devel-2021.8.22-3.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libntfs-3g87-2021.8.22-3.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ntfs-3g-2021.8.22-3.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ntfsprogs-2021.8.22-3.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ntfsprogs-extra-2021.8.22-3.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libntfs-3g-devel / libntfs-3g87 / ntfs-3g / ntfsprogs / etc');
}
