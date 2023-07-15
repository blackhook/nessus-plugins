#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1088.
#

include("compat.inc");

if (description)
{
  script_id(118043);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2018-11645", "CVE-2018-15908", "CVE-2018-15909", "CVE-2018-15910", "CVE-2018-15911", "CVE-2018-16509", "CVE-2018-16511", "CVE-2018-16513", "CVE-2018-16539", "CVE-2018-16540", "CVE-2018-16541", "CVE-2018-16542", "CVE-2018-16585", "CVE-2018-16802");
  script_xref(name:"ALAS", value:"2018-1088");

  script_name(english:"Amazon Linux 2 : ghostscript (ALAS-2018-1088)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the ghostscript .shfill operator did not
properly validate certain types. An attacker could possibly exploit
this to bypass the -dSAFER protection and crash ghostscript or,
possibly, execute arbitrary code in the ghostscript context via a
specially crafted PostScript document.(CVE-2018-15909)

An issue was discovered in Artifex Ghostscript before 9.24. A type
confusion in 'ztype' could be used by remote attackers able to supply
crafted PostScript to crash the interpreter or possibly have
unspecified other impact.(CVE-2018-16511)

An issue was discovered in Artifex Ghostscript before 9.24. The
.setdistillerkeys PostScript command is accepted even though it is not
intended for use during document processing (e.g., after the startup
phase). This leads to memory corruption, allowing remote attackers
able to supply crafted PostScript to crash the interpreter or possibly
have unspecified other impact.(CVE-2018-16585)

It was discovered that the ghostscript PDF14 compositor did not
properly handle the copying of a device. An attacker could possibly
exploit this to bypass the -dSAFER protection and crash ghostscript
or, possibly, execute arbitrary code in the ghostscript context via a
specially crafted PostScript document.(CVE-2018-16540)

It was discovered that the ghostscript device cleanup did not properly
handle devices replaced with a null device. An attacker could possibly
exploit this to bypass the -dSAFER protection and crash ghostscript
or, possibly, execute arbitrary code in the ghostscript context via a
specially crafted PostScript document.(CVE-2018-16541)

It was discovered that the ghostscript did not properly restrict
access to files open prior to enabling the -dSAFER mode. An attacker
could possibly exploit this to bypass the -dSAFER protection and
disclose the content of affected files via a specially crafted
PostScript document.(CVE-2018-16539)

An issue was discovered in Artifex Ghostscript before 9.25. Incorrect
'restoration of privilege' checking when running out of stack during
exception handling could be used by attackers able to supply crafted
PostScript to execute code using the 'pipe' instruction. This is due
to an incomplete fix for CVE-2018-16509 .(CVE-2018-16802)

It was discovered that ghostscript did not properly handle certain
stack overflow error conditions. An attacker could possibly exploit
this to bypass the -dSAFER protection and crash ghostscript or,
possibly, execute arbitrary code in the ghostscript context via a
specially crafted PostScript document.(CVE-2018-16542)

Ghostscript did not honor the -dSAFER option when executing the
'status' instruction, which can be used to retrieve information such
as a file's existence and size. A specially crafted postscript
document could use this flow to gain information on the targeted
system's filesystem content.(CVE-2018-11645)

It was discovered that the ghostscript did not properly validate the
operands passed to the setcolor function. An attacker could possibly
exploit this to bypass the -dSAFER protection and crash ghostscript
or, possibly, execute arbitrary code in the ghostscript context via a
specially crafted PostScript document.(CVE-2018-16513)

It was discovered that the type of the LockDistillerParams parameter
is not properly verified. An attacker could possibly exploit this to
bypass the -dSAFER protection and crash ghostscript or, possibly,
execute arbitrary code in the ghostscript context via a specially
crafted PostScript document.(CVE-2018-15910)

It was discovered that the ghostscript /invalidaccess checks fail
under certain conditions. An attacker could possibly exploit this to
bypass the -dSAFER protection and, for example, execute arbitrary
shell commands via a specially crafted PostScript
document.(CVE-2018-16509)

It was discovered that ghostscript did not properly verify the key
used in aesdecode. An attacker could possibly exploit this to bypass
the -dSAFER protection and crash ghostscript or, possibly, execute
arbitrary code in the ghostscript context via a specially crafted
PostScript document.(CVE-2018-15911)

It was discovered that the ghostscript .tempfile function did not
properly handle file permissions. An attacker could possibly exploit
this to exploit this to bypass the -dSAFER protection and delete files
or disclose their content via a specially crafted PostScript
document.(CVE-2018-15908)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1088.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ghostscript' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ghostscript Failed Restore Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

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


flag = 0;
if (rpm_check(release:"AL2", reference:"ghostscript-9.06-8.amzn2.0.5")) flag++;
if (rpm_check(release:"AL2", reference:"ghostscript-cups-9.06-8.amzn2.0.5")) flag++;
if (rpm_check(release:"AL2", reference:"ghostscript-debuginfo-9.06-8.amzn2.0.5")) flag++;
if (rpm_check(release:"AL2", reference:"ghostscript-devel-9.06-8.amzn2.0.5")) flag++;
if (rpm_check(release:"AL2", reference:"ghostscript-doc-9.06-8.amzn2.0.5")) flag++;
if (rpm_check(release:"AL2", reference:"ghostscript-gtk-9.06-8.amzn2.0.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-cups / ghostscript-debuginfo / etc");
}
