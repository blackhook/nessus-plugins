#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-975-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100602);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-8295", "CVE-2017-9061", "CVE-2017-9062", "CVE-2017-9063", "CVE-2017-9064", "CVE-2017-9065");

  script_name(english:"Debian DLA-975-1 : wordpress security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in wordpress, a web blogging
tool. The Common Vulnerabilities and Exposures project identifies the
following issues.

CVE-2017-8295

Potential unauthorized password reset vulnerability. More information
are available at :

https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset
-0day-CVE-2017-8295.html

CVE-2017-9061

A cross-site scripting (XSS) vulnerability exists when someone
attempts to upload very large files.

CVE-2017-9062

Improper handling of post meta data values in the XML-RPC API.

CVE-2017-9063

Cross-site scripting (XSS) vulnerability in the customizer.

CVE-2017-9064

A Cross Site Request Forgery (CSRF) vulnerability exists in the
filesystem credentials dialog.

CVE-2017-9065

Lack of capability checks for post meta data in the XML-RPC API.

For Debian 7 'Wheezy', these problems have been fixed in version
3.6.1+dfsg-1~deb7u15.

We recommend that you upgrade your wordpress packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a4aa4f1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wordpress"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected wordpress, and wordpress-l10n packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"wordpress", reference:"3.6.1+dfsg-1~deb7u15")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress-l10n", reference:"3.6.1+dfsg-1~deb7u15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
