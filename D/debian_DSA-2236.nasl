#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2236. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53880);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1407");
  script_xref(name:"DSA", value:"2236");

  script_name(english:"Debian DSA-2236-1 : exim4 - command injection");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Exim, Debian's default mail transfer agent, is
vulnerable to command injection attacks in its DKIM processing code,
leading to arbitrary code execution. (CVE-2011-1407 )

The default configuration supplied by Debian does not expose this
vulnerability.

The oldstable distribution (lenny) is not affected by this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2236"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the exim4 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4.72-6+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"exim4", reference:"4.72-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-base", reference:"4.72-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-config", reference:"4.72-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-daemon-heavy", reference:"4.72-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.72-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-daemon-light", reference:"4.72-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-daemon-light-dbg", reference:"4.72-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-dbg", reference:"4.72-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"exim4-dev", reference:"4.72-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"eximon4", reference:"4.72-6+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
