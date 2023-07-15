#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139953);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-14651",
    "CVE-2018-14653"
  );

  script_name(english:"EulerOS 2.0 SP8 : glusterfs (EulerOS-SA-2020-1850)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glusterfs packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - It was found that the fix for CVE-2018-10927,
    CVE-2018-10928, CVE-2018-10929, CVE-2018-10930, and
    CVE-2018-10926 was incomplete. A remote, authenticated
    attacker could use one of these flaws to execute
    arbitrary code, create arbitrary files, or cause denial
    of service on glusterfs server nodes via symlinks to
    relative paths.(CVE-2018-14651)

  - The Gluster file system through versions 4.1.4 and 3.12
    is vulnerable to a heap-based buffer overflow in the
    '__server_getspec' function via the 'gf_getspec_req'
    RPC message. A remote authenticated attacker could
    exploit this to cause a denial of service or other
    potential unspecified impact.(CVE-2018-14653)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1850
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1410aa1");
  script_set_attribute(attribute:"solution", value:
"Update the affected glusterfs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-extra-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-gluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["glusterfs-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-api-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-api-devel-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-cli-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-client-xlators-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-devel-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-extra-xlators-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-fuse-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-libs-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-rdma-4.1.5-1.h3.eulerosv2r8",
        "glusterfs-server-4.1.5-1.h3.eulerosv2r8",
        "python2-gluster-4.1.5-1.h3.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
