#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4053. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104940);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-16943", "CVE-2017-16944");
  script_xref(name:"DSA", value:"4053");

  script_name(english:"Debian DSA-4053-1 : exim4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Exim, a mail transport
agent. The Common Vulnerabilities and Exposures project identifies the
following issues :

  - CVE-2017-16943
    A use-after-free vulnerability was discovered in Exim's
    routines responsible for parsing mail headers. A remote
    attacker can take advantage of this flaw to cause Exim
    to crash, resulting in a denial of service, or
    potentially for remote code execution.

  - CVE-2017-16944
    It was discovered that Exim does not properly handle
    BDAT data headers allowing a remote attacker to cause
    Exim to crash, resulting in a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=882648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=882671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4053"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the exim4 packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.89-2+deb9u2. Default installations disable advertising
the ESMTP CHUNKING extension and are not affected by these issues."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/01");
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
if (deb_check(release:"9.0", prefix:"exim4", reference:"4.89-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-base", reference:"4.89-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-config", reference:"4.89-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-heavy", reference:"4.89-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.89-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-light", reference:"4.89-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-light-dbg", reference:"4.89-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-dbg", reference:"4.89-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-dev", reference:"4.89-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"eximon4", reference:"4.89-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
