#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1295.
#

include("compat.inc");

if (description)
{
  script_id(129565);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/23");

  script_cve_id("CVE-2019-13224", "CVE-2019-13225");
  script_xref(name:"ALAS", value:"2019-1295");

  script_name(english:"Amazon Linux AMI : oniguruma (ALAS-2019-1295)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A use-after-free in onig_new_deluxe() in regext.c in Oniguruma 6.9.2
allows attackers to potentially cause information disclosure, denial
of service, or possibly code execution by providing a crafted regular
expression. The attacker provides a pair of a regex pattern and a
string, with a multi-byte encoding that gets handled by
onig_new_deluxe(). Oniguruma issues often affect Ruby, as well as
common optional libraries for PHP and Rust. (CVE-2019-13224)

A NULL pointer Dereference in match_at() in regexec.c in Oniguruma
6.9.2 allows attackers to potentially cause denial of service by
providing a crafted regular expression. Oniguruma issues often affect
Ruby, as well as common optional libraries for PHP and Rust.
(CVE-2019-13225)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1295.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update oniguruma' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:oniguruma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:oniguruma-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:oniguruma-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"oniguruma-5.9.6-4.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"oniguruma-debuginfo-5.9.6-4.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"oniguruma-devel-5.9.6-4.4.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "oniguruma / oniguruma-debuginfo / oniguruma-devel");
}
