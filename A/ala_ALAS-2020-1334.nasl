#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1334.
#

include("compat.inc");

if (description)
{
  script_id(133004);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/21");

  script_cve_id("CVE-2018-10871", "CVE-2019-10224", "CVE-2019-14824", "CVE-2019-3883");
  script_xref(name:"ALAS", value:"2020-1334");

  script_name(english:"Amazon Linux AMI : 389-ds-base (ALAS-2020-1334)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"389-ds-base before versions 1.3.8.5, 1.4.0.12 is vulnerable to a
Cleartext Storage of Sensitive Information. By default, when the
Replica and/or retroChangeLog plugins are enabled, 389-ds-base stores
passwords in plaintext format in their respective changelog files. An
attacker with sufficiently high privileges, such as root or Directory
Manager, can query these files in order to retrieve plaintext
passwords.(CVE-2018-10871)

A flaw has been found in 389-ds-base versions 1.4.x.x before 1.4.1.3.
When executed in verbose mode, the dscreate and dsconf commands may
display sensitive information, such as the Directory Manager password.
An attacker, able to see the screen or record the terminal standard
error output, could use this flaw to gain sensitive
information.(CVE-2019-10224)

A flaw was found in the 'deref' plugin of 389-ds-base where it could
use the 'search' permission to display attribute values. In some
configurations, this could allow an authenticated attacker to view
private attributes, such as password hashes.(CVE-2019-14824)

In 389-ds-base up to version 1.4.1.2, requests are handled by workers
threads. Each sockets will be waited by the worker for at most
'ioblocktimeout' seconds. However this timeout applies only for
un-encrypted requests. Connections using SSL/TLS are not taking this
timeout into account during reads, and may hang longer.An
unauthenticated attacker could repeatedly create hanging LDAP requests
to hang all the workers, resulting in a Denial of
Service.(CVE-2019-3883)

It was found that encrypted connections did not honor the
'ioblocktimeout' parameter to end blocking requests. As a result, an
unauthenticated attacker could repeatedly start a sufficient number of
encrypted connections to block all workers, resulting in a denial of
service.(CVE-2019-3883)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1334.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update 389-ds-base' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10871");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");
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
if (rpm_check(release:"ALA", reference:"389-ds-base-1.3.9.1-12.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"389-ds-base-debuginfo-1.3.9.1-12.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"389-ds-base-devel-1.3.9.1-12.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"389-ds-base-libs-1.3.9.1-12.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"389-ds-base-snmp-1.3.9.1-12.65.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
}
