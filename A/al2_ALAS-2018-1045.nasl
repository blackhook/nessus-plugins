#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1045.
#

include("compat.inc");

if (description)
{
  script_id(111605);
  script_version("1.3");
  script_cvs_date("Date: 2019/05/07 12:34:16");

  script_cve_id("CVE-2018-12020");
  script_xref(name:"ALAS", value:"2018-1045");

  script_name(english:"Amazon Linux 2 : gnupg2 (ALAS-2018-1045)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A data validation flaw was found in the way gnupg processes file names
during decryption and signature validation. An attacker may be able to
inject messages into gnupg verbose message logging which may have the
potential to bypass the integrity of signature authentication
mechanisms and could have other unintended consequences if
applications take action(s) based on parsed verbose gnupg
output.(CVE-2018-12020)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1045.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update gnupg2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnupg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnupg2-smime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"gnupg2-2.0.22-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"gnupg2-debuginfo-2.0.22-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"gnupg2-smime-2.0.22-5.amzn2.0.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg2 / gnupg2-debuginfo / gnupg2-smime");
}
