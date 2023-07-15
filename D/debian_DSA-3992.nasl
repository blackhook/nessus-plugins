#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3992. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103715);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000100", "CVE-2017-1000101", "CVE-2017-1000254");
  script_xref(name:"DSA", value:"3992");

  script_name(english:"Debian DSA-3992-1 : curl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in cURL, an URL transfer
library. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2017-1000100
    Even Rouault reported that cURL does not properly handle
    long file names when doing an TFTP upload. A malicious
    HTTP(S) server can take advantage of this flaw by
    redirecting a client using the cURL library to a crafted
    TFTP URL and trick it to send private memory contents to
    a remote server over UDP.

  - CVE-2017-1000101
    Brian Carpenter and Yongji Ouyang reported that cURL
    contains a flaw in the globbing function that parses the
    numerical range, leading to an out-of-bounds read when
    parsing a specially crafted URL.

  - CVE-2017-1000254
    Max Dymond reported that cURL contains an out-of-bounds
    read flaw in the FTP PWD response parser. A malicious
    server can take advantage of this flaw to effectively
    prevent a client using the cURL library to work with it,
    causing a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=871554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=871555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=877671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3992"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the curl packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 7.38.0-4+deb8u6.

For the stable distribution (stretch), these problems have been fixed
in version 7.52.1-5+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/09");
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
if (deb_check(release:"8.0", prefix:"curl", reference:"7.38.0-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3", reference:"7.38.0-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-dbg", reference:"7.38.0-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-gnutls", reference:"7.38.0-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-nss", reference:"7.38.0-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-doc", reference:"7.38.0-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-gnutls-dev", reference:"7.38.0-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-nss-dev", reference:"7.38.0-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-openssl-dev", reference:"7.38.0-4+deb8u6")) flag++;
if (deb_check(release:"9.0", prefix:"curl", reference:"7.52.1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3", reference:"7.52.1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-dbg", reference:"7.52.1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-gnutls", reference:"7.52.1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-nss", reference:"7.52.1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-doc", reference:"7.52.1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-gnutls-dev", reference:"7.52.1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-nss-dev", reference:"7.52.1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-openssl-dev", reference:"7.52.1-5+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
