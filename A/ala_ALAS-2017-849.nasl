#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-849.
#

include("compat.inc");

if (description)
{
  script_id(101002);
  script_version("3.4");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-2295");
  script_xref(name:"ALAS", value:"2017-849");

  script_name(english:"Amazon Linux AMI : puppet3 (ALAS-2017-849)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Unsafe YAML deserialization :

Versions of Puppet prior to 4.10.1 will deserialize data off the wire
(from the agent to the server, in this case) with a attacker-specified
format. This could be used to force YAML deserialization in an unsafe
manner, which would lead to remote code execution. This change
constrains the format of data on the wire to PSON or safely decoded
YAML. (CVE-2017-2295 )"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-849.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update puppet3' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:puppet3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:puppet3-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"puppet3-3.7.4-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"puppet3-server-3.7.4-1.13.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "puppet3 / puppet3-server");
}
