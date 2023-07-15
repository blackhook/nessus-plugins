#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1426.
#

include('compat.inc');

if (description)
{
  script_id(136749);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-8616", "CVE-2020-8617");
  script_xref(name:"ALAS", value:"2020-1426");
  script_xref(name:"IAVA", value:"2020-A-0217-S");

  script_name(english:"Amazon Linux 2 : bind (ALAS-2020-1426)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An assertion failure was found in BIND, which checks the validity of
messages containing TSIG resource records. This flaw allows an
attacker that knows or successfully guesses the name of the TSIG key
used by the server to use a specially crafted message, potentially
causing a BIND server to reach an inconsistent state or cause a denial
of service. A majority of BIND servers have an internally-generated
TSIG session key whose name is trivially guessable, and that key
exposes the vulnerability unless specifically disabled.
(CVE-2020-8617)

A flaw was found in BIND, where it does not sufficiently limit the
number of fetches that can be performed while processing a referral
response. This flaw allows an attacker to cause a denial of service
attack. The attacker can also exploit this behavior to use the
recursing server as a reflector in a reflection attack with a high
amplification factor. (CVE-2020-8616)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1426.html");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"bind-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-chroot-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-debuginfo-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-devel-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-export-devel-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-export-libs-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-libs-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-libs-lite-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-license-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-lite-devel-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-devel-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-libs-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-utils-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-sdb-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-sdb-chroot-9.11.4-9.P2.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"bind-utils-9.11.4-9.P2.amzn2.0.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / etc");
}
