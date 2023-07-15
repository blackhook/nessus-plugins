#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1076.
#

include("compat.inc");

if (description)
{
  script_id(117590);
  script_version("1.1");
  script_cvs_date("Date: 2018/09/19 10:04:09");

  script_cve_id("CVE-2018-1063");
  script_xref(name:"ALAS", value:"2018-1076");

  script_name(english:"Amazon Linux 2 : policycoreutils (ALAS-2018-1076)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Context relabeling of filesystems is vulnerable to symbolic link
attack, allowing a local, unprivileged malicious entity to change the
SELinux context of an arbitrary file to a context with few
restrictions. This only happens when the relabeling process is done,
usually when taking SELinux state from disabled to enable (permissive
or enforcing).(CVE-2018-1063)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1076.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update policycoreutils' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-newrole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-restorecond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-sandbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/19");
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
if (rpm_check(release:"AL2", reference:"policycoreutils-2.5-22.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"policycoreutils-debuginfo-2.5-22.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"policycoreutils-devel-2.5-22.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"policycoreutils-gui-2.5-22.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"policycoreutils-newrole-2.5-22.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"policycoreutils-python-2.5-22.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"policycoreutils-restorecond-2.5-22.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"policycoreutils-sandbox-2.5-22.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "policycoreutils / policycoreutils-debuginfo / policycoreutils-devel / etc");
}
