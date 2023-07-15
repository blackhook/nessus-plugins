#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1006.
#

include("compat.inc");

if (description)
{
  script_id(109366);
  script_version("1.3");
  script_cvs_date("Date: 2018/08/31 12:25:00");

  script_cve_id("CVE-2018-1106");
  script_xref(name:"ALAS", value:"2018-1006");

  script_name(english:"Amazon Linux 2 : PackageKit (ALAS-2018-1006)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Authentication bypass allows to install signed packages without
administrator privileges

An authentication bypass flaw has been found in PackageKit that allows
users without administrator privileges to install signed packages. A
local attacker can use this vulnerability to install vulnerable
packages to further compromise a system. (CVE-2018-1106)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1006.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update PackageKit' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit-command-not-found");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit-yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:PackageKit-yum-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-1.1.5-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-command-not-found-1.1.5-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-cron-1.1.5-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-debuginfo-1.1.5-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-glib-1.1.5-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-glib-devel-1.1.5-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-gstreamer-plugin-1.1.5-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-gtk3-module-1.1.5-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-yum-1.1.5-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"PackageKit-yum-plugin-1.1.5-2.amzn2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit / PackageKit-command-not-found / PackageKit-cron / etc");
}
