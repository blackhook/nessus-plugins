#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-355.
#

include("compat.inc");

if (description)
{
  script_id(78298);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/06");

  script_cve_id("CVE-2013-4588");
  script_xref(name:"ALAS", value:"2014-355");

  script_name(english:"Amazon Linux AMI : glibc (ALAS-2014-355)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple stack-based buffer overflows in
net/netfilter/ipvs/ip_vs_ctl.c in the Linux kernel before 2.6.33, when
CONFIG_IP_VS is used, allow local users to gain privileges by
leveraging the CAP_NET_ADMIN capability for (1) a getsockopt system
call, related to the do_ip_vs_get_ctl function, or (2) a setsockopt
system call, related to the do_ip_vs_set_ctl function."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-355.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update glibc' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"glibc-2.17-55.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-common-2.17-55.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-debuginfo-2.17-55.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-debuginfo-common-2.17-55.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-devel-2.17-55.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-headers-2.17-55.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-static-2.17-55.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-utils-2.17-55.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nscd-2.17-55.84.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
}
