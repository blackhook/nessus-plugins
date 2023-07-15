#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1363.
#

include("compat.inc");

if (description)
{
  script_id(136624);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/19");

  script_cve_id("CVE-2019-3814", "CVE-2019-7524");
  script_xref(name:"ALAS", value:"2020-1363");

  script_name(english:"Amazon Linux AMI : dovecot (ALAS-2020-1363)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In Dovecot before 2.2.36.3 and 2.3.x before 2.3.5.1, a local attacker
can cause a buffer overflow in the indexer-worker process, which can
be used to elevate to root. This occurs because of missing checks in
the fts and pop3-uidl components. (CVE-2019-7524)

It was discovered that Dovecot before versions 2.2.36.1 and 2.3.4.1
incorrectly handled client certificates. A remote attacker in
possession of a valid certificate with an empty username field could
possibly use this issue to impersonate other users. (CVE-2019-3814)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1363.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update dovecot' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dovecot-pigeonhole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");
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
if (rpm_check(release:"ALA", reference:"dovecot-2.2.36-6.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-debuginfo-2.2.36-6.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-devel-2.2.36-6.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-mysql-2.2.36-6.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-pgsql-2.2.36-6.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dovecot-pigeonhole-2.2.36-6.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-debuginfo / dovecot-devel / dovecot-mysql / etc");
}
