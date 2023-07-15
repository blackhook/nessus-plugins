#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136228);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-10904",
    "CVE-2018-10907",
    "CVE-2018-10913",
    "CVE-2018-10914",
    "CVE-2018-10923",
    "CVE-2018-10926",
    "CVE-2018-10927",
    "CVE-2018-10928",
    "CVE-2018-10929",
    "CVE-2018-10930"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : glusterfs (EulerOS-SA-2020-1525)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glusterfs packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in RPC request using gfs3_rename_req
    in glusterfs server. An authenticated attacker could
    use this flaw to write to a destination outside the
    gluster volume.(CVE-2018-10930)

  - A flaw was found in RPC request using gfs2_create_req
    in glusterfs server. An authenticated attacker could
    use this flaw to create arbitrary files and execute
    arbitrary code on glusterfs server
    nodes.(CVE-2018-10929)

  - A flaw was found in RPC request using gfs3_symlink_req
    in glusterfs server which allows symlink destinations
    to point to file paths outside of the gluster volume.
    An authenticated attacker could use this flaw to create
    arbitrary symlinks pointing anywhere on the server and
    execute arbitrary code on glusterfs server
    nodes.(CVE-2018-10928)

  - A flaw was found in RPC request using gfs3_lookup_req
    in glusterfs server. An authenticated attacker could
    use this flaw to leak information and execute remote
    denial of service by crashing gluster brick
    process.(CVE-2018-10927)

  - A flaw was found in RPC request using gfs3_mknod_req
    supported by glusterfs server. An authenticated
    attacker could use this flaw to write files to an
    arbitrary location via path traversal and execute
    arbitrary code on a glusterfs server
    node.(CVE-2018-10926)

  - It was found that glusterfs server does not properly
    sanitize file paths in the 'trusted.io-stats-dump'
    extended attribute which is used by the
    'debug/io-stats' translator. Attacker can use this flaw
    to create files and execute arbitrary code. To exploit
    this attacker would require sufficient access to modify
    the extended attributes of files on a gluster
    volume.(CVE-2018-10904)

  - It was found that glusterfs server is vulnerable to
    multiple stack based buffer overflows due to functions
    in server-rpc-fopc.c allocating fixed size buffers
    using 'alloca(3)'. An authenticated attacker could
    exploit this by mounting a gluster volume and sending a
    string longer that the fixed buffer size to cause crash
    or potential code execution.(CVE-2018-10907)

  - An information disclosure vulnerability was discovered
    in glusterfs server. An attacker could issue a xattr
    request via glusterfs FUSE to determine the existence
    of any file.(CVE-2018-10913)

  - It was found that an attacker could issue a xattr
    request via glusterfs FUSE to cause gluster brick
    process to crash which will result in a remote denial
    of service. If gluster multiplexing is enabled this
    will result in a crash of multiple bricks and gluster
    volumes.(CVE-2018-10914)

  - It was found that the 'mknod' call derived from
    mknod(2) can create files pointing to devices on a
    glusterfs server node. An authenticated attacker could
    use this to create an arbitrary device and read data
    from any device attached to the glusterfs server
    node.(CVE-2018-10923)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1525
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4bb456c");
  script_set_attribute(attribute:"solution", value:
"Update the affected glusterfs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["glusterfs-3.8.4-54.15.h7",
        "glusterfs-api-3.8.4-54.15.h7",
        "glusterfs-client-xlators-3.8.4-54.15.h7",
        "glusterfs-libs-3.8.4-54.15.h7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs");
}
