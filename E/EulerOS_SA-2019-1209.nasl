#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123895);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2018-15911",
    "CVE-2018-16802",
    "CVE-2018-16863",
    "CVE-2018-17183",
    "CVE-2018-17961",
    "CVE-2018-18073",
    "CVE-2018-18284",
    "CVE-2018-19134",
    "CVE-2018-19409"
  );
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"EulerOS Virtualization 2.5.4 : ghostscript (EulerOS-SA-2019-1209)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ghostscript package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - It was discovered that ghostscript did not properly
    verify the key used in aesdecode. An attacker could
    possibly exploit this to bypass the -dSAFER protection
    and crash ghostscript or, possibly, execute arbitrary
    code in the ghostscript context via a specially crafted
    PostScript document.i1/4^CVE-2018-15911i1/4%0

  - An issue was discovered in Artifex Ghostscript before
    9.25. Incorrect 'restoration of privilege' checking
    when running out of stack during exception handling
    could be used by attackers able to supply crafted
    PostScript to execute code using the 'pipe'
    instruction. This is due to an incomplete fix for
    CVE-2018-16509.i1/4^CVE-2018-16802i1/4%0

  - It was found that RHSA-2018:2918 did not fully fix
    CVE-2018-16509. An attacker could possibly exploit
    another variant of the flaw and bypass the -dSAFER
    protection to, for example, execute arbitrary shell
    commands via a specially crafted PostScript
    document.i1/4^CVE-2018-16863i1/4%0

  - Artifex Ghostscript before 9.25 allowed a user-writable
    error exception table, which could be used by remote
    attackers able to supply crafted PostScript to
    potentially overwrite or replace error handlers to
    inject code.i1/4^CVE-2018-17183i1/4%0

  - Artifex Ghostscript 9.25 and earlier allows attackers
    to bypass a sandbox protection mechanism via vectors
    involving errorhandler setup. NOTE: this issue exists
    because of an incomplete fix for
    CVE-2018-17183.i1/4^CVE-2018-17961i1/4%0

  - Artifex Ghostscript allows attackers to bypass a
    sandbox protection mechanism by leveraging exposure of
    system operators in the saved execution stack in an
    error object.i1/4^CVE-2018-18073i1/4%0

  - Artifex Ghostscript 9.25 and earlier allows attackers
    to bypass a sandbox protection mechanism via vectors
    involving the 1Policy operator.i1/4^CVE-2018-18284i1/4%0

  - In Artifex Ghostscript through 9.25, the setpattern
    operator did not properly validate certain types. A
    specially crafted PostScript document could exploit
    this to crash Ghostscript or, possibly, execute
    arbitrary code in the context of the Ghostscript
    process. This is a type confusion issue because of
    failure to check whether the Implementation of a
    pattern dictionary was a structure
    type.i1/4^CVE-2018-19134i1/4%0

  - An issue was discovered in Artifex Ghostscript before
    9.26. LockSafetyParams is not checked correctly if
    another device is used.i1/4^CVE-2018-19409i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1209
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cc83d96");
  script_set_attribute(attribute:"solution", value:
"Update the affected ghostscript packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16863");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-19409");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.5.4") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.4");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ghostscript-9.07-31.6.h1"];

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
