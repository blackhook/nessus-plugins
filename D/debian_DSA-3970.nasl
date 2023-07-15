#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3970. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103147);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14482");
  script_xref(name:"DSA", value:"3970");

  script_name(english:"Debian DSA-3970-1 : emacs24 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Charles A. Roelli discovered that Emacs is vulnerable to arbitrary
code execution when rendering text/enriched MIME data (e.g. when using
Emacs-based mail clients)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=875448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/emacs24"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/emacs24"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3970"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the emacs24 packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 24.4+1-5+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 24.5+1-11+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"emacs24", reference:"24.4+1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"emacs24-bin-common", reference:"24.4+1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"emacs24-common", reference:"24.4+1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"emacs24-dbg", reference:"24.4+1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"emacs24-el", reference:"24.4+1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"emacs24-lucid", reference:"24.4+1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"emacs24-lucid-dbg", reference:"24.4+1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"emacs24-nox", reference:"24.4+1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"emacs24-nox-dbg", reference:"24.4+1-5+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"emacs24", reference:"24.5+1-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"emacs24-bin-common", reference:"24.5+1-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"emacs24-common", reference:"24.5+1-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"emacs24-dbg", reference:"24.5+1-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"emacs24-el", reference:"24.5+1-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"emacs24-lucid", reference:"24.5+1-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"emacs24-lucid-dbg", reference:"24.5+1-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"emacs24-nox", reference:"24.5+1-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"emacs24-nox-dbg", reference:"24.5+1-11+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
