#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1081.
#

include("compat.inc");

if (description)
{
  script_id(117605);
  script_version("1.1");
  script_cvs_date("Date: 2018/09/20 11:29:32");

  script_cve_id("CVE-2018-1000024", "CVE-2018-1000027");
  script_xref(name:"ALAS", value:"2018-1081");

  script_name(english:"Amazon Linux AMI : squid (ALAS-2018-1081)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Squid Software Foundation Squid HTTP Caching Proxy contains a NULL
pointer Dereference vulnerability in HTTP Response X-Forwarded-For
header processing that can result in Denial of Service to all clients
of the proxy. This attack appear to be exploitable via Remote HTTP
server responding with an X-Forwarded-For header to certain types of
HTTP request.(CVE-2018-1000027)

The Squid Software Foundation Squid HTTP Caching Proxy contains a
Incorrect Pointer Handling vulnerability in ESI Response Processing
that can result in Denial of Service for all clients using the proxy..
This attack appear to be exploitable via Remote server delivers an
HTTP response payload containing valid but unusual ESI
syntax.(CVE-2018-1000024)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1081.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update squid' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"squid-3.5.20-11.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"squid-debuginfo-3.5.20-11.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"squid-migration-script-3.5.20-11.35.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-debuginfo / squid-migration-script");
}
