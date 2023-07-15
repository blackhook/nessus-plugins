#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4525. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129026);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2019-14822");
  script_xref(name:"DSA", value:"4525");

  script_name(english:"Debian DSA-4525-1 : ibus - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Simon McVittie reported a flaw in ibus, the Intelligent Input Bus. Due
to a misconfiguration during the setup of the DBus, any unprivileged
user could monitor and send method calls to the ibus bus of another
user, if able to discover the UNIX socket used by another user
connected on a graphical environment. The attacker can take advantage
of this flaw to intercept keystrokes of the victim user or modify
input related configurations through DBus method calls."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=940267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/ibus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ibus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/ibus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4525"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ibus packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 1.5.14-3+deb9u2.

For the stable distribution (buster), this problem has been fixed in
version 1.5.19-4+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ibus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"gir1.2-ibus-1.0", reference:"1.5.19-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ibus", reference:"1.5.19-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ibus-doc", reference:"1.5.19-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ibus-gtk", reference:"1.5.19-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ibus-gtk3", reference:"1.5.19-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ibus-wayland", reference:"1.5.19-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libibus-1.0-5", reference:"1.5.19-4+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libibus-1.0-dev", reference:"1.5.19-4+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-ibus-1.0", reference:"1.5.14-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ibus", reference:"1.5.14-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ibus-dbg", reference:"1.5.14-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ibus-doc", reference:"1.5.14-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ibus-gtk", reference:"1.5.14-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ibus-gtk3", reference:"1.5.14-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ibus-wayland", reference:"1.5.14-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libibus-1.0-5", reference:"1.5.14-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libibus-1.0-dev", reference:"1.5.14-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
