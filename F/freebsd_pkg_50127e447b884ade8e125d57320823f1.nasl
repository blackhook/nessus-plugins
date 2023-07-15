#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104759);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14695", "CVE-2017-14696");

  script_name(english:"FreeBSD : salt -- multiple vulnerabilities (50127e44-7b88-4ade-8e12-5d57320823f1)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SaltStack reports :

Directory traversal vulnerability in minion id validation in
SaltStack. Allows remote minions with incorrect credentials to
authenticate to a master via a crafted minion ID. Credit for
discovering the security flaw goes to: Julian Brost
(julian@0x4a42.net). NOTE: this vulnerability exists because of an
incomplete fix for CVE-2017-12791.

Remote Denial of Service with a specially crafted authentication
request. Credit for discovering the security flaw goes to: Julian
Brost (julian@0x4a42.net)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.saltstack.com/en/latest/topics/releases/2017.7.2.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.saltstack.com/en/2016.11/topics/releases/2016.11.8.html"
  );
  # https://github.com/saltstack/salt/commit/80d90307b07b3703428ecbb7c8bb468e28a9ae6d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e282fff1"
  );
  # https://github.com/saltstack/salt/commit/5f8b5e1a0f23fe0f2be5b3c3e04199b57a53db5b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb9d9f53"
  );
  # https://vuxml.freebsd.org/freebsd/50127e44-7b88-4ade-8e12-5d57320823f1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d13c7fd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-salt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"py27-salt<2016.11.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-salt>=2017.7.0<2017.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-salt<2016.11.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-salt>=2017.7.0<2017.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-salt<2016.11.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-salt>=2017.7.0<2017.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-salt<2016.11.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-salt>=2017.7.0<2017.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-salt<2016.11.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-salt>=2017.7.0<2017.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-salt<2016.11.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-salt>=2017.7.0<2017.7.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
