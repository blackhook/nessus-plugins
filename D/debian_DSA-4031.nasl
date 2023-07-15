#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4031. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104503);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-0898", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033");
  script_xref(name:"DSA", value:"4031");

  script_name(english:"Debian DSA-4031-1 : ruby2.3 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the interpreter for
the Ruby language. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2017-0898
    aerodudrizzt reported a buffer underrun vulnerability in
    the sprintf method of the Kernel module resulting in
    heap memory corruption or information disclosure from
    the heap.

  - CVE-2017-0903
    Max Justicz reported that RubyGems is prone to an unsafe
    object deserialization vulnerability. When parsed by an
    application which processes gems, a specially crafted
    YAML formatted gem specification can lead to remote code
    execution.

  - CVE-2017-10784
    Yusuke Endoh discovered an escape sequence injection
    vulnerability in the Basic authentication of WEBrick. An
    attacker can take advantage of this flaw to inject
    malicious escape sequences to the WEBrick log and
    potentially execute control characters on the victim's
    terminal emulator when reading logs.

  - CVE-2017-14033
    asac reported a buffer underrun vulnerability in the
    OpenSSL extension. A remote attacker can take advantage
    of this flaw to cause the Ruby interpreter to crash
    leading to a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=875928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=875931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=875936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=879231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-0898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-0903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-14033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ruby2.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4031"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby2.3 packages.

For the stable distribution (stretch), these problems have been fixed
in version 2.3.3-1+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");
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
if (deb_check(release:"9.0", prefix:"libruby2.3", reference:"2.3.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ruby2.3", reference:"2.3.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ruby2.3-dev", reference:"2.3.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ruby2.3-doc", reference:"2.3.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ruby2.3-tcltk", reference:"2.3.3-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
