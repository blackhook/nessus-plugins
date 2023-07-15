#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4297. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117611);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_xref(name:"DSA", value:"4297");

  script_name(english:"Debian DSA-4297-1 : chromium-browser - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in the chromium web browser.
Kevin Cheung discovered an error in the WebAssembly implementation and
evil1m0 discovered a URL spoofing issue."
  );
  # https://security-tracker.debian.org/tracker/source-package/chromium-browser
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e33901a2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4297"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (stretch), this problem has been fixed in
version 69.0.3497.92-1~deb9u1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/20");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"69.0.3497.92-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"69.0.3497.92-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"69.0.3497.92-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"69.0.3497.92-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"69.0.3497.92-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"69.0.3497.92-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
