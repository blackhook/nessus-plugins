#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99796);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-4444",
    "CVE-2016-4446",
    "CVE-2016-4989"
  );

  script_name(english:"EulerOS 2.0 SP1 : setroubleshoot, setroubleshoot-plugins (EulerOS-SA-2016-1033)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the setroubleshoot,
setroubleshoot-plugins packages installed, the EulerOS installation
on the remote host is affected by the following vulnerabilities :

  - The setroubleshoot packages provide tools to help
    diagnose SELinux problems. When Access Vector Cache
    (AVC) messages are returned, an alert can be generated
    that provides information about the problem and helps
    to track its resolution.

  - The setroubleshoot-plugins package provides a set of
    analysis plugins for use with setroubleshoot. Each
    plugin has the capacity to analyze SELinux AVC data and
    system data to provide user friendly reports describing
    how to interpret SELinux AVC denials.

  - Security Fix(es)i1/4s

  - Shell command injection flaws were found in the way the
    setroubleshoot executed external commands. A local
    attacker able to trigger certain SELinux denials could
    use these flaws to execute arbitrary code with
    privileges of the setroubleshoot user.(CVE-2016-4989)

  - Shell command injection flaws were found in the way the
    setroubleshoot allow_execmod and allow_execstack
    plugins executed external commands. A local attacker
    able to trigger an execmod or execstack SELinux denial
    could use these flaws to execute arbitrary code with
    privileges of the setroubleshoot user.
    (CVE-2016-4444,CVE-2016-4446)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1033
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dea1151");
  script_set_attribute(attribute:"solution", value:
"Update the affected setroubleshoot, setroubleshoot-plugins packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:setroubleshoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:setroubleshoot-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:setroubleshoot-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["setroubleshoot-3.2.24-4",
        "setroubleshoot-plugins-3.0.59-2",
        "setroubleshoot-server-3.2.24-4"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "setroubleshoot, setroubleshoot-plugins");
}
