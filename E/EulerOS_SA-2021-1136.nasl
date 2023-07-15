#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145777);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2020-10753", "CVE-2020-27781");

  script_name(english:"EulerOS 2.0 SP8 : ceph (EulerOS-SA-2021-1136)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ceph packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - User credentials can be manipulated and stolen by
    Native CephFS consumers of OpenStack Manila, resulting
    in potential privilege escalation. An Open Stack Manila
    user can request access to a share to an arbitrary
    cephx user, including existing users. The access key is
    retrieved via the interface drivers. Then, all users of
    the requesting OpenStack project can view the access
    key. This enables the attacker to target any resource
    that the user has access to. This can be done to even
    'admin' users, compromising the ceph administrator.
    This flaw affects Ceph versions prior to 14.2.16, 15.x
    prior to 15.2.8, and 16.x prior to
    16.2.0.(CVE-2020-27781)

  - A flaw was found in the Red Hat Ceph Storage RadosGW
    (Ceph Object Gateway). The vulnerability is related to
    the injection of HTTP headers via a CORS ExposeHeader
    tag. The newline character in the ExposeHeader tag in
    the CORS configuration file generates a header
    injection in the response when the CORS request is
    made. Ceph versions 3.x and 4.x are vulnerable to this
    issue.(CVE-2020-10753)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1136
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce36b79b");
  script_set_attribute(attribute:"solution", value:
"Update the affected ceph packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10753");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-27781");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-rbd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["ceph-12.2.8-1.h9.eulerosv2r8",
        "librados2-12.2.8-1.h9.eulerosv2r8",
        "librbd1-12.2.8-1.h9.eulerosv2r8",
        "python-rados-12.2.8-1.h9.eulerosv2r8",
        "python-rbd-12.2.8-1.h9.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph");
}
