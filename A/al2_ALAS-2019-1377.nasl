#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1377.
#

include("compat.inc");

if (description)
{
  script_id(132265);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/23");

  script_cve_id("CVE-2018-17336");
  script_xref(name:"ALAS", value:"2019-1377");

  script_name(english:"Amazon Linux 2 : udisks2 (ALAS-2019-1377)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"UDisks 2.8.0 has a format string vulnerability in udisks_log in
udiskslogging.c, allowing attackers to obtain sensitive information
(stack contents), cause a denial of service (memory corruption), or
possibly have unspecified other impact via a malformed filesystem
label, as demonstrated by %d or %n substrings.(CVE-2018-17336)

An uncontrolled format string vulnerability has been discovered in
udisks when it mounts a filesystem with a malformed label. A local
attacker may use this flaw to leak memory, make the udisks service
crash, or cause other unspecified effects.(CVE-2018-17336)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1377.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update udisks2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libudisks2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libudisks2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:udisks2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:udisks2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:udisks2-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:udisks2-lsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:udisks2-lvm2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"libudisks2-2.7.3-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libudisks2-devel-2.7.3-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"udisks2-2.7.3-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"udisks2-debuginfo-2.7.3-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"udisks2-iscsi-2.7.3-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"udisks2-lsm-2.7.3-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"udisks2-lvm2-2.7.3-9.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libudisks2 / libudisks2-devel / udisks2 / udisks2-debuginfo / etc");
}
