#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4159. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108771);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-0493");
  script_xref(name:"DSA", value:"4159");

  script_name(english:"Debian DSA-4159-1 : remctl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Santosh Ananthakrishnan discovered a use-after-free in remctl, a
server for Kerberos-authenticated command execution. If the command is
configured with the sudo option, this could potentially result in the
execution of arbitrary code.

The oldstable distribution (jessie) is not affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/remctl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/remctl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4159"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the remctl packages.

For the stable distribution (stretch), this problem has been fixed in
version 3.13-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:remctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libnet-remctl-perl", reference:"3.13-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libremctl-dev", reference:"3.13-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libremctl1", reference:"3.13-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"php-remctl", reference:"3.13-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-remctl", reference:"3.13-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"remctl-client", reference:"3.13-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"remctl-server", reference:"3.13-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ruby-remctl", reference:"3.13-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
