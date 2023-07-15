##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1598.
##

include('compat.inc');

if (description)
{
  script_id(146633);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/05");

  script_cve_id(
    "CVE-2018-17183",
    "CVE-2018-17961",
    "CVE-2018-18073",
    "CVE-2018-18284",
    "CVE-2018-19134",
    "CVE-2018-19409",
    "CVE-2018-19475",
    "CVE-2018-19476",
    "CVE-2018-19477",
    "CVE-2019-3835",
    "CVE-2019-3838",
    "CVE-2019-3839",
    "CVE-2019-6116",
    "CVE-2019-14811",
    "CVE-2019-14812",
    "CVE-2019-14813",
    "CVE-2019-14817",
    "CVE-2019-14869"
  );
  script_bugtraq_id(
    105990,
    106154,
    106278,
    106700,
    107451,
    107452,
    107494,
    107520,
    107855,
    108441
  );
  script_xref(name:"ALAS", value:"2021-1598");

  script_name(english:"Amazon Linux 2 : ghostscript (ALAS-2021-1598)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of ghostscript installed on the remote host is prior to 9.25-5. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1598 advisory.

  - Artifex Ghostscript before 9.25 allowed a user-writable error exception table, which could be used by
    remote attackers able to supply crafted PostScript to potentially overwrite or replace error handlers to
    inject code. (CVE-2018-17183)

  - Artifex Ghostscript 9.25 and earlier allows attackers to bypass a sandbox protection mechanism via vectors
    involving errorhandler setup. NOTE: this issue exists because of an incomplete fix for CVE-2018-17183.
    (CVE-2018-17961)

  - Artifex Ghostscript allows attackers to bypass a sandbox protection mechanism by leveraging exposure of
    system operators in the saved execution stack in an error object. (CVE-2018-18073)

  - Artifex Ghostscript 9.25 and earlier allows attackers to bypass a sandbox protection mechanism via vectors
    involving the 1Policy operator. (CVE-2018-18284)

  - In Artifex Ghostscript through 9.25, the setpattern operator did not properly validate certain types. A
    specially crafted PostScript document could exploit this to crash Ghostscript or, possibly, execute
    arbitrary code in the context of the Ghostscript process. This is a type confusion issue because of
    failure to check whether the Implementation of a pattern dictionary was a structure type. (CVE-2018-19134)

  - An issue was discovered in Artifex Ghostscript before 9.26. LockSafetyParams is not checked correctly if
    another device is used. (CVE-2018-19409)

  - psi/zdevice2.c in Artifex Ghostscript before 9.26 allows remote attackers to bypass intended access
    restrictions because available stack space is not checked when the device remains the same.
    (CVE-2018-19475)

  - psi/zicc.c in Artifex Ghostscript before 9.26 allows remote attackers to bypass intended access
    restrictions because of a setcolorspace type confusion. (CVE-2018-19476)

  - psi/zfjbig2.c in Artifex Ghostscript before 9.26 allows remote attackers to bypass intended access
    restrictions because of a JBIG2Decode type confusion. (CVE-2018-19477)

  - A flaw was found in, ghostscript versions prior to 9.50, in the .pdf_hook_DSC_Creator procedure where it
    did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A
    specially crafted PostScript file could disable security protection and then have access to the file
    system, or execute arbitrary commands. (CVE-2019-14811)

  - A flaw was found in all ghostscript versions 9.x before 9.50, in the .setuserparams2 procedure where it
    did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A
    specially crafted PostScript file could disable security protection and then have access to the file
    system, or execute arbitrary commands. (CVE-2019-14812)

  - A flaw was found in ghostscript, versions 9.x before 9.50, in the setsystemparams procedure where it did
    not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A specially
    crafted PostScript file could disable security protection and then have access to the file system, or
    execute arbitrary commands. (CVE-2019-14813)

  - A flaw was found in, ghostscript versions prior to 9.50, in the .pdfexectoken and other procedures where
    it did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A
    specially crafted PostScript file could disable security protection and then have access to the file
    system, or execute arbitrary commands. (CVE-2019-14817)

  - A flaw was found in all versions of ghostscript 9.x before 9.50, where the `.charkeys` procedure, where it
    did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. An
    attacker could abuse this flaw by creating a specially crafted PostScript file that could escalate
    privileges within the Ghostscript and access files outside of restricted areas or execute commands.
    (CVE-2019-14869)

  - It was found that the superexec operator was available in the internal dictionary in ghostscript before
    9.27. A specially crafted PostScript file could use this flaw in order to, for example, have access to the
    file system outside of the constrains imposed by -dSAFER. (CVE-2019-3835)

  - It was found that the forceput operator could be extracted from the DefineResource method in ghostscript
    before 9.27. A specially crafted PostScript file could use this flaw in order to, for example, have access
    to the file system outside of the constrains imposed by -dSAFER. (CVE-2019-3838)

  - It was found that in ghostscript some privileged operators remained accessible from various places after
    the CVE-2019-6116 fix. A specially crafted PostScript file could use this flaw in order to, for example,
    have access to the file system outside of the constrains imposed by -dSAFER. Ghostscript versions before
    9.27 are vulnerable. (CVE-2019-3839)

  - In Artifex Ghostscript through 9.26, ephemeral or transient procedures can allow access to system
    operators, leading to remote code execution. (CVE-2019-6116)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1598.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17183");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17961");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-18073");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-18284");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19134");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19409");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19475");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19476");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19477");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14811");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14812");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14813");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14817");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14869");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3835");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3838");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3839");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-6116");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ghostscript' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'ghostscript-9.25-5.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'ghostscript-9.25-5.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'ghostscript-9.25-5.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'ghostscript-cups-9.25-5.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'ghostscript-cups-9.25-5.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'ghostscript-cups-9.25-5.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'ghostscript-debuginfo-9.25-5.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'ghostscript-debuginfo-9.25-5.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'ghostscript-debuginfo-9.25-5.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'ghostscript-doc-9.25-5.amzn2', 'release':'AL2'},
    {'reference':'ghostscript-gtk-9.25-5.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'ghostscript-gtk-9.25-5.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'ghostscript-gtk-9.25-5.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libgs-9.25-5.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libgs-9.25-5.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libgs-9.25-5.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'libgs-devel-9.25-5.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'libgs-devel-9.25-5.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'libgs-devel-9.25-5.amzn2', 'cpu':'x86_64', 'release':'AL2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-cups / ghostscript-debuginfo / etc");
}