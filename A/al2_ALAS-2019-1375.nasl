#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1375.
#

include("compat.inc");

if (description)
{
  script_id(132263);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/28");

  script_cve_id("CVE-2019-13616", "CVE-2019-14906");
  script_xref(name:"ALAS", value:"2019-1375");

  script_name(english:"Amazon Linux 2 : SDL (ALAS-2019-1375)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow flaw, in SDL while copying an existing
surface into a new optimized one, due to a lack of validation while
loading a BMP image, is possible. An application that uses SDL to
parse untrusted input files may be vulnerable to this flaw, which
could allow an attacker to make the application crash or execute
code.(CVE-2019-14906)

SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9
has a heap-based buffer over-read in BlitNtoN in video/SDL_blit_N.c
when called from SDL_SoftBlit in video/SDL_blit.c.(CVE-2019-13616)

A heap-based buffer overflow was discovered in SDL in the
SDL_BlitCopy() function, that was called while copying an existing
surface into a new optimized one, due to lack of validation while
loading a BMP image in the SDL_LoadBMP_RW() function. An application
that uses SDL to parse untrusted input files may be vulnerable to this
flaw, which could allow an attacker to make the application crash or
possibly execute code.(CVE-2019-13616)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1375.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update SDL' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14906");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:SDL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:SDL-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:SDL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:SDL-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"SDL-1.2.15-15.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"SDL-debuginfo-1.2.15-15.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"SDL-devel-1.2.15-15.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"SDL-static-1.2.15-15.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SDL / SDL-debuginfo / SDL-devel / SDL-static");
}
