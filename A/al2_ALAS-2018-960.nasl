#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-960.
#

include("compat.inc");

if (description)
{
  script_id(109128);
  script_version("1.1");
  script_cvs_date("Date: 2018/04/18 15:09:32");

  script_cve_id("CVE-2017-14604");
  script_xref(name:"ALAS", value:"2018-960");

  script_name(english:"Amazon Linux 2 : nautilus (ALAS-2018-960)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Insufficient validation of trust of .desktop files with execute
permission

An untrusted .desktop file with executable permission set could choose
its displayed name and icon, and execute commands without warning when
opened by the user. An attacker could use this flaw to trick a user
into opening a .desktop file disguised as a document, such as a PDF,
and execute arbitrary commands.(CVE-2017-14604)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-960.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update nautilus' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nautilus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"nautilus-3.22.3-4.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"nautilus-debuginfo-3.22.3-4.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"nautilus-devel-3.22.3-4.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"nautilus-extensions-3.22.3-4.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nautilus / nautilus-debuginfo / nautilus-devel / etc");
}
