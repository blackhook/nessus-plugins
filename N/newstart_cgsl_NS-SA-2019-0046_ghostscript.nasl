#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0046. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127227);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2018-15908",
    "CVE-2018-15909",
    "CVE-2018-15911",
    "CVE-2018-16511",
    "CVE-2018-16539",
    "CVE-2018-16541",
    "CVE-2018-16802",
    "CVE-2018-16863",
    "CVE-2018-17183",
    "CVE-2018-17961",
    "CVE-2018-18073",
    "CVE-2018-18284",
    "CVE-2018-19134",
    "CVE-2018-19409"
  );
  script_bugtraq_id(105122, 105178, 107451);
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : ghostscript Multiple Vulnerabilities (NS-SA-2019-0046)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has ghostscript packages installed that are
affected by multiple vulnerabilities:

  - An issue was discovered in Artifex Ghostscript before
    9.26. LockSafetyParams is not checked correctly if
    another device is used. (CVE-2018-19409)

  - It was discovered that the ghostscript .tempfile
    function did not properly handle file permissions. An
    attacker could possibly exploit this to exploit this to
    bypass the -dSAFER protection and delete files or
    disclose their content via a specially crafted
    PostScript document. (CVE-2018-15908)

  - An issue was discovered in Artifex Ghostscript before
    9.25. Incorrect restoration of privilege checking when
    running out of stack during exception handling could be
    used by attackers able to supply crafted PostScript to
    execute code using the pipe instruction. This is due
    to an incomplete fix for CVE-2018-16509.
    (CVE-2018-16802)

  - It was discovered that the ghostscript device cleanup
    did not properly handle devices replaced with a null
    device. An attacker could possibly exploit this to
    bypass the -dSAFER protection and crash ghostscript or,
    possibly, execute arbitrary code in the ghostscript
    context via a specially crafted PostScript document.
    (CVE-2018-16541)

  - It was discovered that ghostscript did not properly
    verify the key used in aesdecode. An attacker could
    possibly exploit this to bypass the -dSAFER protection
    and crash ghostscript or, possibly, execute arbitrary
    code in the ghostscript context via a specially crafted
    PostScript document. (CVE-2018-15911)

  - It was discovered that the ghostscript did not properly
    restrict access to files open prior to enabling the
    -dSAFER mode. An attacker could possibly exploit this to
    bypass the -dSAFER protection and disclose the content
    of affected files via a specially crafted PostScript
    document. (CVE-2018-16539)

  - Artifex Ghostscript before 9.25 allowed a user-writable
    error exception table, which could be used by remote
    attackers able to supply crafted PostScript to
    potentially overwrite or replace error handlers to
    inject code. (CVE-2018-17183)

  - Artifex Ghostscript 9.25 and earlier allows attackers to
    bypass a sandbox protection mechanism via vectors
    involving errorhandler setup. NOTE: this issue exists
    because of an incomplete fix for CVE-2018-17183.
    (CVE-2018-17961)

  - Artifex Ghostscript allows attackers to bypass a sandbox
    protection mechanism by leveraging exposure of system
    operators in the saved execution stack in an error
    object. (CVE-2018-18073)

  - Artifex Ghostscript 9.25 and earlier allows attackers to
    bypass a sandbox protection mechanism via vectors
    involving the 1Policy operator. (CVE-2018-18284)

  - It was found that RHSA-2018:2918 did not fully fix
    CVE-2018-16509. An attacker could possibly exploit
    another variant of the flaw and bypass the -dSAFER
    protection to, for example, execute arbitrary shell
    commands via a specially crafted PostScript document.
    (CVE-2018-16863)

  - In Artifex Ghostscript through 9.25, the setpattern
    operator did not properly validate certain types. A
    specially crafted PostScript document could exploit this
    to crash Ghostscript or, possibly, execute arbitrary
    code in the context of the Ghostscript process. This is
    a type confusion issue because of failure to check
    whether the Implementation of a pattern dictionary was a
    structure type. (CVE-2018-19134)

  - It was discovered that the ghostscript .shfill operator
    did not properly validate certain types. An attacker
    could possibly exploit this to bypass the -dSAFER
    protection and crash ghostscript or, possibly, execute
    arbitrary code in the ghostscript context via a
    specially crafted PostScript document. (CVE-2018-15909)

  - It was discovered that the ghostscript .type operator
    did not properly validate its operands. A specially
    crafted PostScript document could exploit this to crash
    ghostscript or, possibly, execute arbitrary code in the
    context of the ghostscript process. (CVE-2018-16511)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0046");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ghostscript packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16863");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-19409");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "ghostscript-9.07-31.el7_6.6",
    "ghostscript-cups-9.07-31.el7_6.6",
    "ghostscript-debuginfo-9.07-31.el7_6.6",
    "ghostscript-devel-9.07-31.el7_6.6",
    "ghostscript-doc-9.07-31.el7_6.6",
    "ghostscript-gtk-9.07-31.el7_6.6"
  ],
  "CGSL MAIN 5.04": [
    "ghostscript-9.07-31.el7_6.6",
    "ghostscript-cups-9.07-31.el7_6.6",
    "ghostscript-debuginfo-9.07-31.el7_6.6",
    "ghostscript-devel-9.07-31.el7_6.6",
    "ghostscript-doc-9.07-31.el7_6.6",
    "ghostscript-gtk-9.07-31.el7_6.6"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
