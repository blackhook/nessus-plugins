#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4259. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111468);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2017-17405", "CVE-2017-17742", "CVE-2017-17790", "CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_xref(name:"DSA", value:"4259");

  script_name(english:"Debian DSA-4259-1 : ruby2.3 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the interpreter for
the Ruby language, which may result in incorrect processing of
HTTP/FTP, directory traversal, command injection, unintended socket
creation or information disclosure.

This update also fixes several issues in RubyGems which could allow an
attacker to use specially crafted gem files to mount cross-site
scripting attacks, cause denial of service through an infinite loop,
write arbitrary files, or run malicious code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/ruby2.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ruby2.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4259"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby2.3 packages.

For the stable distribution (stretch), these problems have been fixed
in version 2.3.3-1+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libruby2.3", reference:"2.3.3-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"ruby2.3", reference:"2.3.3-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"ruby2.3-dev", reference:"2.3.3-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"ruby2.3-doc", reference:"2.3.3-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"ruby2.3-tcltk", reference:"2.3.3-1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
