#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1369.
#

include('compat.inc');

if (description)
{
  script_id(137092);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-8616", "CVE-2020-8617");
  script_xref(name:"ALAS", value:"2020-1369");

  script_name(english:"Amazon Linux AMI : bind (ALAS-2020-1369)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A malicious actor who intentionally exploits this lack of effective
limitation on the number of fetches performed when processing
referrals can, through the use of specially crafted referrals, cause a
recursing server to issue a very large number of fetches in an attempt
to process the referral. This has at least two potential effects: The
performance of the recursing server can potentially be degraded by the
additional work required to perform these fetches, and The attacker
can exploit this behavior to use the recursing server as a reflector
in a reflection attack with a high amplification
factor.(CVE-2020-8616)

Using a specially crafted message, an attacker may potentially cause a
BIND server to reach an inconsistent state if the attacker knows (or
successfully guesses) the name of a TSIG key used by the server. Since
BIND, by default, configures a local session key even on servers whose
configuration does not otherwise make use of it, almost all current
BIND servers are vulnerable. In releases of BIND dating from March
2018 and after, an assertion check in tsig.c detects this inconsistent
state and deliberately exits. Prior to the introduction of the check
the server would continue operating in an inconsistent state, with
potentially harmful results.(CVE-2020-8617)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1369.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update bind' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8617");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"ALA", reference:"bind-9.8.2-0.68.rc1.64.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-chroot-9.8.2-0.68.rc1.64.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-debuginfo-9.8.2-0.68.rc1.64.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-devel-9.8.2-0.68.rc1.64.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-libs-9.8.2-0.68.rc1.64.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-sdb-9.8.2-0.68.rc1.64.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-utils-9.8.2-0.68.rc1.64.amzn1")) flag++;

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
