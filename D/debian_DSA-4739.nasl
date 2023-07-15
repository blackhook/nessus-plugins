#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4739. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139298);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id("CVE-2020-9862", "CVE-2020-9893", "CVE-2020-9894", "CVE-2020-9895", "CVE-2020-9915", "CVE-2020-9925");
  script_xref(name:"DSA", value:"4739");

  script_name(english:"Debian DSA-4739-1 : webkit2gtk - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The following vulnerabilities have been discovered in the webkit2gtk
web engine :

  - CVE-2020-9862
    Ophir Lojkine discovered that copying a URL from the Web
    Inspector may lead to command injection.

  - CVE-2020-9893
    0011 discovered that a remote attacker may be able to
    cause unexpected application termination or arbitrary
    code execution.

  - CVE-2020-9894
    0011 discovered that a remote attacker may be able to
    cause unexpected application termination or arbitrary
    code execution.

  - CVE-2020-9895
    Wen Xu discovered that a remote attacker may be able to
    cause unexpected application termination or arbitrary
    code execution.

  - CVE-2020-9915
    Ayoub Ait Elmokhtar discovered that processing
    maliciously crafted web content may prevent Content
    Security Policy from being enforced.

  - CVE-2020-9925
    An anonymous researcher discovered that processing
    maliciously crafted web content may lead to universal
    cross site scripting."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-9862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-9893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-9894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-9895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-9915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-9925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/webkit2gtk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/webkit2gtk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4739"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the webkit2gtk packages.

For the stable distribution (buster), these problems have been fixed
in version 2.28.4-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webkit2gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"gir1.2-javascriptcoregtk-4.0", reference:"2.28.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-webkit2-4.0", reference:"2.28.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjavascriptcoregtk-4.0-18", reference:"2.28.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjavascriptcoregtk-4.0-bin", reference:"2.28.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjavascriptcoregtk-4.0-dev", reference:"2.28.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-37", reference:"2.28.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-37-gtk2", reference:"2.28.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-dev", reference:"2.28.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-doc", reference:"2.28.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"webkit2gtk-driver", reference:"2.28.4-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
