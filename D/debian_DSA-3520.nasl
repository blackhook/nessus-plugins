#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3520. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90031);
  script_version("2.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-1950", "CVE-2016-1954", "CVE-2016-1957", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1964", "CVE-2016-1966", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_xref(name:"DSA", value:"3520");

  script_name(english:"Debian DSA-3520-1 : icedove - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail client: Multiple memory safety errors,
integer overflows, buffer overflows and other implementation errors
may lead to the execution of arbitrary code or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3520"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 38.7.0-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 38.7.0-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"calendar-google-provider", reference:"38.7.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove", reference:"38.7.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dbg", reference:"38.7.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dev", reference:"38.7.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceowl-extension", reference:"38.7.0-1~deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"calendar-google-provider", reference:"38.7.0-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove", reference:"38.7.0-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove-dbg", reference:"38.7.0-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove-dev", reference:"38.7.0-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceowl-extension", reference:"38.7.0-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
