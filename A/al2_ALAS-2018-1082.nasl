#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1082.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(117710);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/21");

  script_cve_id("CVE-2018-5740");
  script_xref(name:"ALAS", value:"2018-1082");

  script_name(english:"Amazon Linux 2 : bind (ALAS-2018-1082)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A denial of service flaw was discovered in bind versions that include
the 'deny-answer-aliases' feature. This flaw may allow a remote
attacker to trigger an INSIST assert in named leading to termination
of the process and a denial of service condition.(CVE-2018-5740)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1082.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update bind' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5740");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"bind-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-chroot-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-debuginfo-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-devel-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-libs-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-libs-lite-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-lite-devel-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-devel-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-libs-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-utils-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-sdb-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-sdb-chroot-9.9.4-61.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"bind-utils-9.9.4-61.amzn2.1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / bind-libs / etc");
}
