#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1390-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110312);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");

  script_name(english:"Debian DLA-1390-1 : procps security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Qualys Research Labs discovered multiple vulnerabilities in
procps, a set of command line and full screen utilities for browsing
procfs. The Common Vulnerabilities and Exposures project identifies
the following problems :

CVE-2018-1122

top read its configuration from the current working directory if no
$HOME was configured. If top were started from a directory writable by
the attacker (such as /tmp) this could result in local privilege
escalation.

CVE-2018-1123

Denial of service against the ps invocation of another user.

CVE-2018-1124

An integer overflow in the file2strvec() function of libprocps could
result in local privilege escalation.

CVE-2018-1125

A stack-based buffer overflow in pgrep could result in denial of
service for a user using pgrep for inspecting a specially crafted
process.

CVE-2018-1126

Incorrect integer size parameters used in wrappers for standard C
allocators could cause integer truncation and lead to integer overflow
issues.

For Debian 7 'Wheezy', these problems have been fixed in version
1:3.3.3-3+deb7u1.

We recommend that you upgrade your procps packages.

The Debian LTS team would like to thank Abhijith PA for preparing this
update.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/05/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/procps"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libprocps0, libprocps0-dev, and procps packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libprocps0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libprocps0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:procps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/05");
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
if (deb_check(release:"7.0", prefix:"libprocps0", reference:"1:3.3.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libprocps0-dev", reference:"1:3.3.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"procps", reference:"1:3.3.3-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
