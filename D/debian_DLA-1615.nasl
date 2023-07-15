#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1615-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119875);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-7108", "CVE-2013-7205", "CVE-2014-1878", "CVE-2016-9566", "CVE-2018-18245");
  script_bugtraq_id(64363, 64489, 65605);

  script_name(english:"Debian DLA-1615-1 : nagios3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues were corrected in nagios3, a monitoring and management
system for hosts, services and networks.

CVE-2018-18245

Maximilian Boehner of usd AG found a cross-site scripting (XSS)
vulnerability in Nagios Core. This vulnerability allows attackers to
place malicious JavaScript code into the web frontend through
manipulation of plugin output. In order to do this the attacker needs
to be able to manipulate the output returned by nagios checks, e.g. by
replacing a plugin on one of the monitored endpoints. Execution of the
payload then requires that an authenticated user creates an alert
summary report which contains the corresponding output.

CVE-2016-9566

It was discovered that local users with access to an account in the
nagios group are able to gain root privileges via a symlink attack on
the debug log file.

CVE-2014-1878

An issue was corrected that allowed remote attackers to cause a
stack-based buffer overflow and subsequently a denial of service
(segmentation fault) via a long message to cmd.cgi.

CVE-2013-7205 | CVE-2013-7108

A flaw was corrected in Nagios that could be exploited to cause a
denial of service. This vulnerability is induced due to an off-by-one
error within the process_cgivars() function, which can be exploited to
cause an out-of-bounds read by sending a specially crafted key value
to the Nagios web UI.

For Debian 8 'Jessie', these problems have been fixed in version
3.5.1.dfsg-2+deb8u1.

We recommend that you upgrade your nagios3 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nagios3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"nagios3", reference:"3.5.1.dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nagios3-cgi", reference:"3.5.1.dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nagios3-common", reference:"3.5.1.dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nagios3-core", reference:"3.5.1.dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nagios3-dbg", reference:"3.5.1.dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nagios3-doc", reference:"3.5.1.dfsg-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
