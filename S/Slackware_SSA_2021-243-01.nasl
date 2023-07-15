#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2021-243-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152969);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

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
    "CVE-2021-39263"
  );

  script_name(english:"Slackware Linux 14.2 / current ntfs-3g  Multiple Vulnerabilities (SSA:2021-243-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to ntfs-3g.");
  script_set_attribute(attribute:"description", value:
"The version of ntfs-3g installed on the remote host is prior to 2021.8.22. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2021-243-01 advisory.

  - A crafted NTFS image can trigger a heap-based buffer overflow, caused by an unsanitized attribute in
    ntfs_get_attribute_value, in NTFS-3G < 2021.8.22. (CVE-2021-39263)

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected ntfs-3g package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39263");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '2021.8.22', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '2021.8.22', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '2021.8.22', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '2021.8.22', 'product' : 'ntfs-3g', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
      severity   : SECURITY_WARNING,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
