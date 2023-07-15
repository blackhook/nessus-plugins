#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1357.
#

include("compat.inc");

if (description)
{
  script_id(130608);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/17");

  script_cve_id("CVE-2018-16548", "CVE-2018-6541");
  script_xref(name:"ALAS", value:"2019-1357");

  script_name(english:"Amazon Linux 2 : zziplib (ALAS-2019-1357)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in ZZIPlib through 0.13.69. There is a memory
leak triggered in the function __zzip_parse_root_directory in zip.c,
which will lead to a denial of service attack.(CVE-2018-16548)

In ZZIPlib 0.13.67, there is a bus error caused by loading of a
misaligned address (when handling disk64_trailer local entries) in
__zzip_fetch_disk_trailer (zzip/zip.c). Remote attackers could
leverage this vulnerability to cause a denial of service via a crafted
zip file.(CVE-2018-6541)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1357.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update zziplib' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:zziplib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:zziplib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:zziplib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:zziplib-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"zziplib-0.13.62-11.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"zziplib-debuginfo-0.13.62-11.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"zziplib-devel-0.13.62-11.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"zziplib-utils-0.13.62-11.amzn2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zziplib / zziplib-debuginfo / zziplib-devel / zziplib-utils");
}
