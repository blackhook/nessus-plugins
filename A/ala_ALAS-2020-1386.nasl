#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1386.
#

include("compat.inc");

if (description)
{
  script_id(138632);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2019-12519", "CVE-2019-12525", "CVE-2019-13345", "CVE-2020-11945");
  script_xref(name:"ALAS", value:"2020-1386");

  script_name(english:"Amazon Linux AMI : squid (ALAS-2020-1386)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An issue was discovered in Squid before 5.0.2. A remote attacker can
replay a sniffed Digest Authentication nonce to gain access to
resources that are otherwise forbidden. This occurs because the
attacker can overflow the nonce reference counter (a short integer).
Remote code execution may occur if the pooled token credentials are
freed (instead of replayed as valid credentials). (CVE-2020-11945)

An issue was discovered in Squid through 4.7. When handling the tag
esi:when when ESI is enabled, Squid calls ESIExpression::Evaluate.
This function uses a fixed stack buffer to hold the expression while
it's being evaluated. When processing the expression, it could either
evaluate the top of the stack, or add a new member to the stack. When
adding a new member, there is no check to ensure that the stack won't
overflow. (CVE-2019-12519)

An issue was discovered in Squid 3.3.9 through 3.5.28 and 4.x through
4.7. When Squid is configured to use Digest authentication, it parses
the header Proxy-Authorization. It searches for certain tokens such as
domain, uri, and qop. Squid checks if this token's value starts with a
quote and ends with one. If so, it performs a memcpy of its length
minus 2. Squid never checks whether the value is just a single quote
(which would satisfy its requirements), leading to a memcpy of its
length minus 1. (CVE-2019-12525)

The cachemgr.cgi web module of Squid through 4.7 has XSS via the
user_name or auth parameter. (CVE-2019-13345)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1386.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update squid' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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
if (rpm_check(release:"ALA", reference:"squid-3.5.20-15.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"squid-debuginfo-3.5.20-15.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"squid-migration-script-3.5.20-15.39.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-debuginfo / squid-migration-script");
}
