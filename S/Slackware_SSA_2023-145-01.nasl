#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-145-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176394);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2021-46790",
    "CVE-2022-30783",
    "CVE-2022-30784",
    "CVE-2022-30785",
    "CVE-2022-30786",
    "CVE-2022-30787",
    "CVE-2022-30788",
    "CVE-2022-30789",
    "CVE-2022-40284"
  );

  script_name(english:"Slackware Linux 14.2 / 15.0 / current ntfs-3g  Multiple Vulnerabilities (SSA:2023-145-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to ntfs-3g.");
  script_set_attribute(attribute:"description", value:
"The version of ntfs-3g installed on the remote host is prior to 2022.10.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2023-145-01 advisory.

  - ntfsck in NTFS-3G through 2021.8.22 has a heap-based buffer overflow involving buffer+512*3-2. NOTE: the
    upstream position is that ntfsck is deprecated; however, it is shipped by some Linux distributions.
    (CVE-2021-46790)

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
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.434772
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74f2144e");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected ntfs-3g package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-40284");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '2022.10.3', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '2022.10.3', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '2022.10.3', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '2022.10.3', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '2022.10.3', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '2022.10.3', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
