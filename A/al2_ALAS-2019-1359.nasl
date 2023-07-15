#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1359.
#

include("compat.inc");

if (description)
{
  script_id(131027);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/12");

  script_cve_id("CVE-2014-6272", "CVE-2015-6525");
  script_xref(name:"ALAS", value:"2019-1359");

  script_name(english:"Amazon Linux 2 : libevent (ALAS-2019-1359)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflows in the evbuffer API in Libevent 1.4.x
before 1.4.15, 2.0.x before 2.0.22, and 2.1.x before 2.1.5-beta allow
context-dependent attackers to cause a denial of service or possibly
have other unspecified impact via 'insanely large inputs' to the (1)
evbuffer_add, (2) evbuffer_expand, or (3) bufferevent_write function,
which triggers a heap-based buffer overflow or an infinite loop. NOTE:
this identifier has been SPLIT per ADT3 due to different affected
versions. See CVE-2015-6525 for the functions that are only affected
in 2.0 and later. (CVE-2014-6272)

Multiple integer overflow flaws were found in the libevent's evbuffer
API. An attacker able to make an application pass an excessively long
input to libevent using the API could use these flaws to make the
application enter an infinite loop, crash, and, possibly, execute
arbitrary code. (CVE-2015-6525)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1359.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libevent' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libevent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libevent-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");
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
if (rpm_check(release:"AL2", reference:"libevent-2.0.21-4.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"libevent-debuginfo-2.0.21-4.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"libevent-devel-2.0.21-4.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"libevent-doc-2.0.21-4.amzn2.0.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libevent / libevent-debuginfo / libevent-devel / libevent-doc");
}
