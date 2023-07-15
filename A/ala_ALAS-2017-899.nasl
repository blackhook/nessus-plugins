#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-899.
#

include("compat.inc");

if (description)
{
  script_id(103651);
  script_version("3.4");
  script_cvs_date("Date: 2019/04/10 16:10:16");

  script_cve_id("CVE-2008-4796", "CVE-2008-7313", "CVE-2013-4214", "CVE-2013-7108", "CVE-2013-7205", "CVE-2014-1878", "CVE-2014-5008", "CVE-2014-5009", "CVE-2016-9566");
  script_xref(name:"ALAS", value:"2017-899");

  script_name(english:"Amazon Linux AMI : nagios (ALAS-2017-899)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple off-by-one errors in Nagios Core 3.5.1, 4.0.2, and earlier,
and Icinga before 1.8.5, 1.9 before 1.9.4, and 1.10 before 1.10.2
allow remote authenticated users to obtain sensitive information from
process memory or cause a denial of service (crash) via a long string
in the last key value in the variable list to the process_cgivars
function in (1) avail.c, (2) cmd.c, (3) config.c, (4) extinfo.c, (5)
histogram.c, (6) notifications.c, (7) outages.c, (8) status.c, (9)
statusmap.c, (10) summary.c, and (11) trends.c in cgi/, which triggers
a heap-based buffer over-read.

Stack-based buffer overflow in the cmd_submitf function in cgi/cmd.c
in Nagios Core, possibly 4.0.3rc1 and earlier, and Icinga before
1.8.6, 1.9 before 1.9.5, and 1.10 before 1.10.3 allows remote
attackers to cause a denial of service (segmentation fault) via a long
message to cmd.cgi.

Various command-execution flaws were found in the Snoopy library
included with Nagios. These flaws allowed remote attackers to execute
arbitrary commands by manipulating Nagios HTTP headers.

A privilege escalation flaw was found in the way Nagios handled log
files. An attacker able to control the Nagios logging configuration
(the 'nagios' user/group) could use this flaw to elevate their
privileges to root.

Off-by-one error in the process_cgivars function in
contrib/daemonchk.c in Nagios Core 3.5.1, 4.0.2, and earlier allows
remote authenticated users to obtain sensitive information from
process memory or cause a denial of service (crash) via a long string
in the last key value in the variable list, which triggers a
heap-based buffer over-read.

rss-newsfeed.php in Nagios Core 3.4.4, 3.5.1, and earlier, when
MAGPIE_CACHE_ON is set to 1, allows local users to overwrite arbitrary
files via a symlink attack on /tmp/magpie_cache.

The _httpsrequest function (Snoopy/Snoopy.class.php) in Snoopy 1.2.3
and earlier, as used in (1) ampache, (2) libphp-snoopy, (3) mahara,
(4) mediamate, (5) opendb, (6) pixelpost, and possibly other products,
allows remote attackers to execute arbitrary commands via shell
metacharacters in https URLs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-899.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update nagios' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nagios-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nagios-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nagios-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"nagios-3.5.1-2.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nagios-common-3.5.1-2.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nagios-debuginfo-3.5.1-2.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nagios-devel-3.5.1-2.10.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios / nagios-common / nagios-debuginfo / nagios-devel");
}
