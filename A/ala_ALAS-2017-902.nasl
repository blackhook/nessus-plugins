#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-902.
#

include("compat.inc");

if (description)
{
  script_id(103572);
  script_version("3.7");
  script_cvs_date("Date: 2018/12/14 16:35:54");

  script_cve_id("CVE-2017-9775", "CVE-2017-9776");
  script_xref(name:"ALAS", value:"2017-902");

  script_name(english:"Amazon Linux AMI : poppler (ALAS-2017-902)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stack-buffer overflow in GfxState.cc :

A stack-based buffer overflow was found in the poppler library. An
attacker could create a malicious PDF file that would cause
applications that use poppler (such as Evince) to crash, or
potentially execute arbitrary code when opened. (CVE-2017-9775)

Integer overflow in JBIG2Stream.cc :

An integer overflow leading to heap-based buffer overflow was found in
the poppler library. An attacker could create a malicious PDF file
that would cause applications that use poppler (such as Evince) to
crash, or potentially execute arbitrary code when opened.
(CVE-2017-9776)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-902.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update poppler' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/02");
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
if (rpm_check(release:"ALA", reference:"poppler-0.26.5-17.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-cpp-0.26.5-17.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-cpp-devel-0.26.5-17.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-debuginfo-0.26.5-17.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-devel-0.26.5-17.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-glib-0.26.5-17.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-glib-devel-0.26.5-17.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-utils-0.26.5-17.17.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-cpp / poppler-cpp-devel / poppler-debuginfo / etc");
}
