#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1447.
#

include("compat.inc");

if (description)
{
  script_id(138049);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/06");

  script_cve_id("CVE-2019-17041", "CVE-2019-17042");
  script_xref(name:"ALAS", value:"2020-1447");

  script_name(english:"Amazon Linux 2 : rsyslog (ALAS-2020-1447)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An issue was discovered in Rsyslog v8.1908.0.
contrib/pmaixforwardedfrom/pmaixforwardedfrom.c has a heap overflow in
the parser for AIX log messages. The parser tries to locate a log
message delimiter (in this case, a space or a colon) but fails to
account for strings that do not satisfy this constraint. If the string
does not match, then the variable lenMsg will reach the value zero and
will skip the sanity check that detects invalid log messages. The
message will then be considered valid, and the parser will eat up the
nonexistent colon delimiter. In doing so, it will decrement lenMsg, a
signed integer, whose value was zero and now becomes minus one. The
following step in the parser is to shift left the contents of the
message. To do this, it will call memmove with the right pointers to
the target and destination strings, but the lenMsg will now be
interpreted as a huge value, causing a heap overflow. (CVE-2019-17041)

An issue was discovered in Rsyslog v8.1908.0.
contrib/pmcisconames/pmcisconames.c has a heap overflow in the parser
for Cisco log messages. The parser tries to locate a log message
delimiter (in this case, a space or a colon), but fails to account for
strings that do not satisfy this constraint. If the string does not
match, then the variable lenMsg will reach the value zero and will
skip the sanity check that detects invalid log messages. The message
will then be considered valid, and the parser will eat up the
nonexistent colon delimiter. In doing so, it will decrement lenMsg, a
signed integer, whose value was zero and now becomes minus one. The
following step in the parser is to shift left the contents of the
message. To do this, it will call memmove with the right pointers to
the target and destination strings, but the lenMsg will now be
interpreted as a huge value, causing a heap overflow. (CVE-2019-17042)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1447.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update rsyslog' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-libdbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-mmaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-mmkubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-mmsnmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rsyslog-udpspoof");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"rsyslog-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-crypto-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-debuginfo-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-doc-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-elasticsearch-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-gnutls-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-gssapi-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-kafka-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-libdbi-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-mmaudit-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-mmjsonparse-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-mmkubernetes-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-mmnormalize-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-mmsnmptrapd-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-mysql-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-pgsql-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-relp-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-snmp-8.24.0-52.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"rsyslog-udpspoof-8.24.0-52.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-crypto / rsyslog-debuginfo / rsyslog-doc / etc");
}
