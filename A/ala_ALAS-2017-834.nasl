#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-834.
#

include('compat.inc');

if (description)
{
  script_id(100554);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2016-2125",
    "CVE-2016-2126",
    "CVE-2017-2619",
    "CVE-2017-7494"
  );
  script_xref(name:"ALAS", value:"2017-834");
  script_xref(name:"RHSA", value:"2017:1270");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Amazon Linux AMI : samba (ALAS-2017-834) (SambaCry)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A remote code execution flaw was found in Samba. A malicious
authenticated

samba client, having write access to the samba share, could use this
flaw to

execute arbitrary code as root. (CVE-2017-7494)

It was found that Samba always requested forwardable tickets when
using Kerberos authentication. A service to which Samba authenticated
using Kerberos could subsequently use the ticket to impersonate Samba
to other services or domain users. (CVE-2016-2125)

A flaw was found in the way Samba handled PAC (Privilege Attribute
Certificate) checksums. A remote, authenticated attacker could use
this flaw to crash the winbindd process. (CVE-2016-2126)

A race condition was found in samba server. A malicious samba client
could use this flaw to access files and directories, in areas of the
server file system not exported under the share definitions.
(CVE-2017-2619)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2017-834.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update samba' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba is_known_pipename() Arbitrary Module Load');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"ALA", reference:"ctdb-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ctdb-tests-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsmbclient-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsmbclient-devel-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwbclient-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwbclient-devel-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-client-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-client-libs-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-libs-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-tools-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-debuginfo-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-devel-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-krb5-printing-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-libs-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-pidl-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-python-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-test-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-test-libs-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-clients-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-krb5-locator-4.4.4-13.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-modules-4.4.4-13.35.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / libsmbclient / libsmbclient-devel / libwbclient / etc");
}
