#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3897. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101034);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-7943", "CVE-2017-6922");
  script_xref(name:"DSA", value:"3897");

  script_name(english:"Debian DSA-3897-1 : drupal7 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in Drupal, a fully-featured
content management framework. The Common Vulnerabilities and Exposures
project identifies the following issues :

  - CVE-2015-7943
    Samuel Mortenson and Pere Orga discovered that the
    overlay module does not sufficiently validate URLs prior
    to displaying their contents, leading to an open
    redirect vulnerability.

  More information can be found at
  https://www.drupal.org/SA-CORE-2015-004

  - CVE-2017-6922
    Greg Knaddison, Mori Sugimoto and iancawthorne
    discovered that files uploaded by anonymous users into a
    private file system can be accessed by other anonymous
    users leading to an access bypass vulnerability.

  More information can be found at
  https://www.drupal.org/SA-CORE-2017-003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=865498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7943"
  );
  # https://www.drupal.org/SA-CORE-2015-004
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?034c342d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6922"
  );
  # https://www.drupal.org/SA-CORE-2017-003
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34ea2f5d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/drupal7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/drupal7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3897"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the drupal7 packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 7.32-1+deb8u9.

For the stable distribution (stretch), these problems have been fixed
in version 7.52-2+deb9u1. For the stable distribution (stretch),
CVE-2015-7943 was already fixed before the initial release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:drupal7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"8.0", prefix:"drupal7", reference:"7.32-1+deb8u9")) flag++;
if (deb_check(release:"9.0", prefix:"drupal7", reference:"7.52-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
