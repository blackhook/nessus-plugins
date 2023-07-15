#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130865);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id(
    "CVE-2019-3827"
  );

  script_name(english:"EulerOS 2.0 SP5 : gvfs (EulerOS-SA-2019-2156)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the gvfs packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerability :

  - An incorrect permission check in the admin backend in
    gvfs before version 1.39.4 was found that allows
    reading and modify arbitrary files by privileged users
    without asking for password when no authentication
    agent is running. This vulnerability can be exploited
    by malicious programs running under privileges of users
    belonging to the wheel group to further escalate its
    privileges by modifying system files without user's
    knowledge. Successful exploitation requires uncommon
    system configuration.(CVE-2019-3827)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2156
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fa4a56c");
  script_set_attribute(attribute:"solution", value:
"Update the affected gvfs package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3827");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["gvfs-1.30.4-5.h3.eulerosv2r7",
        "gvfs-afc-1.30.4-5.h3.eulerosv2r7",
        "gvfs-afp-1.30.4-5.h3.eulerosv2r7",
        "gvfs-archive-1.30.4-5.h3.eulerosv2r7",
        "gvfs-client-1.30.4-5.h3.eulerosv2r7",
        "gvfs-devel-1.30.4-5.h3.eulerosv2r7",
        "gvfs-fuse-1.30.4-5.h3.eulerosv2r7",
        "gvfs-goa-1.30.4-5.h3.eulerosv2r7",
        "gvfs-gphoto2-1.30.4-5.h3.eulerosv2r7",
        "gvfs-mtp-1.30.4-5.h3.eulerosv2r7",
        "gvfs-smb-1.30.4-5.h3.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvfs");
}
