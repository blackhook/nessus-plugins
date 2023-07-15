#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-699.
#

include("compat.inc");

if (description)
{
  script_id(91047);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718");
  script_xref(name:"ALAS", value:"2016-699");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Amazon Linux AMI : ImageMagick (ALAS-2016-699) (ImageTragick)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that ImageMagick did not properly sanitize certain
input before passing it to the delegate functionality. A remote
attacker could create a specially crafted image that, when processed
by an application using ImageMagick or an unsuspecting user using the
ImageMagick utilities, would lead to arbitrary execution of shell
commands with the privileges of the user running the application.
(CVE-2016-3714)

It was discovered that certain ImageMagick coders and pseudo-protocols
did not properly prevent security sensitive operations when processing
specially crafted images. A remote attacker could create a specially
crafted image that, when processed by an application using ImageMagick
or an unsuspecting user using the ImageMagick utilities, would allow
the attacker to disclose the contents of arbitrary files.
(CVE-2016-3715 , CVE-2016-3716 , CVE-2016-3717)

A server-side request forgery flaw was discovered in the way
ImageMagick processed certain images. A remote attacker could exploit
this flaw to mislead an application using ImageMagick or an
unsuspecting user using the ImageMagick utilities into, for example,
performing HTTP(S) requests or opening FTP sessions via specially
crafted images. (CVE-2016-3718)

Note: This update contains an updated /etc/ImageMagick/policy.xml file
that disables the EPHEMERAL, HTTPS, HTTP, URL, FTP, MVG, MSL, TEXT,
and LABEL coders. If you experience any problems after the update, it
may be necessary to manually adjust the policy.xml file to match your
requirements. Please take additional precautions to ensure that your
applications using the ImageMagick library do not process malicious or
untrusted files before doing so."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-699.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ImageMagick' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"ImageMagick-6.7.8.9-13.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-c++-6.7.8.9-13.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-c++-devel-6.7.8.9-13.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-debuginfo-6.7.8.9-13.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-devel-6.7.8.9-13.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-doc-6.7.8.9-13.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-perl-6.7.8.9-13.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
