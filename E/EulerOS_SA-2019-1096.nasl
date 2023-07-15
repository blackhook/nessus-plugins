#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123109);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-15126",
    "CVE-2018-20019",
    "CVE-2018-20020",
    "CVE-2018-20022",
    "CVE-2018-20024",
    "CVE-2018-20748",
    "CVE-2018-20749",
    "CVE-2018-20750",
    "CVE-2018-6307"
  );

  script_name(english:"EulerOS 2.0 SP3 : libvncserver (EulerOS-SA-2019-1096)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libvncserver package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - LibVNC before 0.9.12 contains multiple heap
    out-of-bounds write vulnerabilities in
    libvncclient/rfbproto.c. The fix for CVE-2018-20019 was
    incomplete.(CVE-2018-20748)

  - LibVNC before 0.9.12 contains a heap out-of-bounds
    write vulnerability in libvncserver/rfbserver.c. The
    fix for CVE-2018-15127 was incomplete.(CVE-2018-20749)

  - LibVNC through 0.9.12 contains a heap out-of-bounds
    write vulnerability in libvncserver/rfbserver.c. The
    fix for CVE-2018-15127 was incomplete.(CVE-2018-20750)

  - LibVNC before commit
    7b1ef0ffc4815cab9a96c7278394152bdc89dc4d contains heap
    out-of-bound write vulnerability inside structure in
    VNC client code that can result remote code
    execution(CVE-2018-20020)

  - LibVNC before commit
    ca2a5ac02fbbadd0a21fabba779c1ea69173d10b contains heap
    use-after-free vulnerability in server code of file
    transfer extension that can result remote code
    execution.(CVE-2018-6307)

  - LibVNC before commit
    73cb96fec028a576a5a24417b57723b55854ad7b contains heap
    use-after-free vulnerability in server code of file
    transfer extension that can result remote code
    execution(CVE-2018-15126)

  - LibVNC before commit
    a83439b9fbe0f03c48eb94ed05729cb016f8b72f contains
    multiple heap out-of-bound write vulnerabilities in VNC
    client code that can result remote code
    execution(CVE-2018-20019)

  - LibVNC before 2f5b2ad1c6c99b1ac6482c95844a84d66bb52838
    contains multiple weaknesses CWE-665: Improper
    Initialization vulnerability in VNC client code that
    allows attacker to read stack memory and can be abuse
    for information disclosure. Combined with another
    vulnerability, it can be used to leak stack memory
    layout and in bypassing ASLR(CVE-2018-20022)

  - LibVNC before commit
    4a21bbd097ef7c44bb000c3bd0907f96a10e4ce7 contains null
    pointer dereference in VNC client code that can result
    DoS.(CVE-2018-20024)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1096
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68e0a741");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvncserver packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvncserver");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libvncserver-0.9.9-12.h10"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvncserver");
}
