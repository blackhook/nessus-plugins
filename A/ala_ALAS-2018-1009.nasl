#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1009.
#

include("compat.inc");

if (description)
{
  script_id(109697);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2016-1549", "CVE-2018-7170", "CVE-2018-7182", "CVE-2018-7183", "CVE-2018-7184", "CVE-2018-7185");
  script_xref(name:"ALAS", value:"2018-1009");

  script_name(english:"Amazon Linux AMI : ntp (ALAS-2018-1009)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ephemeral association time spoofing additional protection

ntpd in ntp 4.2.x before 4.2.8p7 and 4.3.x before 4.3.92 allows
authenticated users that know the private symmetric key to create
arbitrarily-many ephemeral associations in order to win the clock
selection of ntpd and modify a victim's clock via a Sybil attack. This
issue exists because of an incomplete fix for CVE-2016-1549
.(CVE-2018-7170)

Interleaved symmetric mode cannot recover from bad state

ntpd in ntp 4.2.8p4 before 4.2.8p11 drops bad packets before updating
the 'received' timestamp, which allows remote attackers to cause a
denial of service (disruption) by sending a packet with a zero-origin
timestamp causing the association to reset and setting the contents of
the packet as the most recent timestamp. This issue is a result of an
incomplete fix for CVE-2015-7704 .(CVE-2018-7184)

Ephemeral association time spoofing

A malicious authenticated peer can create arbitrarily-many ephemeral
associations in order to win the clock selection algorithm in ntpd in
NTP 4.2.8p4 and earlier and NTPsec
3e160db8dc248a0bcb053b56a80167dc742d2b74 and
a5fb34b9cc89b92a8fef2f459004865c93bb7f92 and modify a victim's
clock.(CVE-2016-1549)

Buffer read overrun leads information leak in ctl_getitem()

The ctl_getitem method in ntpd in ntp-4.2.8p6 before 4.2.8p11 allows
remote attackers to cause a denial of service (out-of-bounds read) via
a crafted mode 6 packet with a ntpd instance from 4.2.8p6 through
4.2.8p10. (CVE-2018-7182)

Unauthenticated packet can reset authenticated interleaved association

The protocol engine in ntp 4.2.6 before 4.2.8p11 allows a remote
attackers to cause a denial of service (disruption) by continually
sending a packet with a zero-origin timestamp and source IP address of
the 'other side' of an interleaved association causing the victim ntpd
to reset its association.(CVE-2018-7185)

decodearr() can write beyond its buffer limit

Buffer overflow in the decodearr function in ntpq in ntp 4.2.8p6
through 4.2.8p10 allows remote attackers to execute arbitrary code by
leveraging an ntpq query and sending a response with a crafted
array.(CVE-2018-7183)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1009.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ntp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"ntp-4.2.8p11-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-debuginfo-4.2.8p11-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-doc-4.2.8p11-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-perl-4.2.8p11-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntpdate-4.2.8p11-1.37.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-doc / ntp-perl / ntpdate");
}
