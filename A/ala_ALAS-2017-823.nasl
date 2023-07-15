#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-823.
#

include("compat.inc");

if (description)
{
  script_id(99711);
  script_version("3.3");
  script_cvs_date("Date: 2018/09/24  9:27:18");

  script_cve_id("CVE-2017-2616");
  script_xref(name:"ALAS", value:"2017-823");

  script_name(english:"Amazon Linux AMI : util-linux (ALAS-2017-823)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sending SIGKILL to other processes with root privileges via su :

A race condition was found in the way su handled the management of
child processes. A local authenticated attacker could use this flaw to
kill other processes with root privileges under specific
conditions.(CVE-2017-2616)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-823.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update util-linux' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"libblkid-2.23.2-33.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libblkid-devel-2.23.2-33.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libmount-2.23.2-33.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libmount-devel-2.23.2-33.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libuuid-2.23.2-33.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libuuid-devel-2.23.2-33.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"util-linux-2.23.2-33.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"util-linux-debuginfo-2.23.2-33.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"uuidd-2.23.2-33.28.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libblkid / libblkid-devel / libmount / libmount-devel / libuuid / etc");
}
