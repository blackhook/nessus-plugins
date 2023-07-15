#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1005.
#

include("compat.inc");

if (description)
{
  script_id(109365);
  script_version("1.4");
  script_cvs_date("Date: 2019/03/21 10:55:56");

  script_cve_id("CVE-2018-1000119", "CVE-2018-1079", "CVE-2018-1086");
  script_xref(name:"ALAS", value:"2018-1005");

  script_name(english:"Amazon Linux 2 : pcs (ALAS-2018-1005)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Debug parameter removal bypass, allowing information disclosure

It was found that the REST interface of the pcsd service did not
properly remove the pcs debug argument from the /run_pcs query,
possibly disclosing sensitive information. A remote attacker with a
valid token could use this flaw to elevate their privilege.
(CVE-2018-1086)

Timing attack in authenticity_token.rb

Sinatra rack-protection versions 1.5.4 and 2.0.0.rc3 and earlier
contains a timing attack vulnerability in the CSRF token checking that
can result in signatures can be exposed. This attack appear to be
exploitable via network connectivity to the ruby application. This
vulnerability appears to have been fixed in 1.5.5 and 2.0.0.
(CVE-2018-1000119)

Privilege escalation via authorized user malicious REST call

It was found that the REST interface of the pcsd service did not
properly sanitize the file name from the /remote/put_file query. If
the /etc/booth directory exists, an authenticated attacker with write
permissions could create or overwrite arbitrary files with arbitrary
data outside of the /etc/booth directory, in the context of the pcsd
process. (CVE-2018-1079)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1005.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update pcs' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcs-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"pcs-0.9.162-5.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"pcs-debuginfo-0.9.162-5.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"pcs-snmp-0.9.162-5.amzn2.1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcs / pcs-debuginfo / pcs-snmp");
}
