#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1380.
#

include("compat.inc");

if (description)
{
  script_id(138053);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/06");

  script_cve_id("CVE-2020-12783");
  script_xref(name:"ALAS", value:"2020-1380");

  script_name(english:"Amazon Linux AMI : exim (ALAS-2020-1380)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Exim through 4.93 has an out-of-bounds read in the SPA authenticator
that could result in SPA/NTLM authentication bypass in auths/spa.c and
auths/auth-spa.c. (CVE-2020-12783)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1380.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update exim' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-greylist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"exim-4.92-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-debuginfo-4.92-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-greylist-4.92-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-mon-4.92-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-mysql-4.92-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-pgsql-4.92-1.26.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-debuginfo / exim-greylist / exim-mon / exim-mysql / etc");
}
