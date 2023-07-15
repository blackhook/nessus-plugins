#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124887);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-15911",
    "CVE-2018-16541",
    "CVE-2018-16802",
    "CVE-2018-17183",
    "CVE-2018-17961",
    "CVE-2018-18073",
    "CVE-2018-18284",
    "CVE-2018-19134",
    "CVE-2018-19409"
  );
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : ghostscript (EulerOS-SA-2019-1384)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ghostscript package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An issue was discovered in Artifex Ghostscript before
    9.26. LockSafetyParams is not checked correctly if
    another device is used.(CVE-2018-19409)

  - In Artifex Ghostscript 9.23 before 2018-08-24,
    attackers able to supply crafted PostScript could use
    uninitialized memory access in the aesdecode operator
    to crash the interpreter or potentially execute
    code.(CVE-2018-15911)

  - In Artifex Ghostscript before 9.24, attackers able to
    supply crafted PostScript files could use incorrect
    free logic in pagedevice replacement to crash the
    interpreter.(CVE-2018-16541)

  - An issue was discovered in Artifex Ghostscript before
    9.25. Incorrect 'restoration of privilege' checking
    when running out of stack during exception handling
    could be used by attackers able to supply crafted
    PostScript to execute code using the 'pipe'
    instruction. This is due to an incomplete fix for
    CVE-2018-16509.(CVE-2018-16802)

  - Artifex Ghostscript before 9.25 allowed a user-writable
    error exception table, which could be used by remote
    attackers able to supply crafted PostScript to
    potentially overwrite or replace error handlers to
    inject code.(CVE-2018-17183)

  - Artifex Ghostscript allows attackers to bypass a
    sandbox protection mechanism by leveraging exposure of
    system operators in the saved execution stack in an
    error object.(CVE-2018-18073)

  - Artifex Ghostscript 9.25 and earlier allows attackers
    to bypass a sandbox protection mechanism via vectors
    involving the 1Policy operator.(CVE-2018-18284)

  - Artifex Ghostscript 9.25 and earlier allows attackers
    to bypass a sandbox protection mechanism via vectors
    involving errorhandler setup. NOTE: this issue exists
    because of an incomplete fix for
    CVE-2018-17183.(CVE-2018-17961)

  - In Artifex Ghostscript through 9.25, the setpattern
    operator did not properly validate certain types. A
    specially crafted PostScript document could exploit
    this to crash Ghostscript or, possibly, execute
    arbitrary code in the context of the Ghostscript
    process. This is a type confusion issue because of
    failure to check whether the Implementation of a
    pattern dictionary was a structure
    type.(CVE-2018-19134)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1384
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfdc9367");
  script_set_attribute(attribute:"solution", value:
"Update the affected ghostscript packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["ghostscript-9.07-31.6.h5"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
