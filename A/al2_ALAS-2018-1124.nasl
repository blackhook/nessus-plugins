#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1124.
#

include("compat.inc");

if (description)
{
  script_id(119507);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/13");

  script_cve_id("CVE-2016-4463");
  script_xref(name:"ALAS", value:"2018-1124");

  script_name(english:"Amazon Linux 2 : xerces-c (ALAS-2018-1124)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack exhaustion flaw was found in the way Xerces-C XML parser
handled deeply nested DTDs. An attacker could potentially use this
flaw to crash an application using Xerces-C by tricking it into
processing specially crafted data.(CVE-2016-4463)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1124.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update xerces-c' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-c-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"xerces-c-3.1.1-9.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"xerces-c-debuginfo-3.1.1-9.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"xerces-c-devel-3.1.1-9.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"xerces-c-doc-3.1.1-9.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-c / xerces-c-debuginfo / xerces-c-devel / xerces-c-doc");
}
