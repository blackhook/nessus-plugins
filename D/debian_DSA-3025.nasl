#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3025. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77715);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-0487", "CVE-2014-0488", "CVE-2014-0489", "CVE-2014-0490");
  script_bugtraq_id(69835, 69836, 69837, 69838);
  script_xref(name:"DSA", value:"3025");

  script_name(english:"Debian DSA-3025-1 : apt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that APT, the high level package manager, does not
properly invalidate unauthenticated data (CVE-2014-0488 ), performs
incorrect verification of 304 replies (CVE-2014-0487 ), does not
perform the checksum check when the Acquire::GzipIndexes option is
used (CVE-2014-0489 ) and does not properly perform validation for
binary packages downloaded by the apt-get download command
(CVE-2014-0490 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-3025"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apt packages.

For the stable distribution (wheezy), these problems have been fixed
in version 0.9.7.9+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"apt", reference:"0.9.7.9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apt-doc", reference:"0.9.7.9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apt-transport-https", reference:"0.9.7.9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"apt-utils", reference:"0.9.7.9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-inst1.5", reference:"0.9.7.9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-pkg-dev", reference:"0.9.7.9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-pkg-doc", reference:"0.9.7.9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libapt-pkg4.12", reference:"0.9.7.9+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
