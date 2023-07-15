#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-358.
#

include("compat.inc");

if (description)
{
  script_id(78301);
  script_version("1.4");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2014-1875");
  script_xref(name:"ALAS", value:"2014-358");

  script_name(english:"Amazon Linux AMI : perl-Capture-Tiny (ALAS-2014-358)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found [1] that the Capture::Tiny module, provided by the
perl-Capture-Tiny package, used the File::temp::tmpnam module to
generate temporary files :

./lib/Capture/Tiny.pm: $stash->{flag_files}{$which} = scalar tmpnam();

This module makes use of the mktemp() function when called in the
scalar context, which creates significantly more predictable temporary
files. Additionally, the temporary file is created with world-writable
(0666) permission. A local attacker could use this flaw to perform a
symbolic link attack, overwriting arbitrary files accessible to a
program using the Capture::Tiny module."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-358.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update perl-Capture-Tiny' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Capture-Tiny");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"perl-Capture-Tiny-0.24-1.5.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-Capture-Tiny");
}
