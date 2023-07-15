#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
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
  script_id(149360);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-22885",
    "CVE-2021-22902",
    "CVE-2021-22903",
    "CVE-2021-22904"
  );

  script_name(english:"FreeBSD : Rails -- multiple vulnerabilities (f7a00ad7-ae75-11eb-8113-08002728f74c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Ruby on Rails blog :

Rails versions 6.1.3.2, 6.0.3.7, and 5.2.6 have been released! These
releases contain important security fixes. Here is a list of the
issues fixed :

CVE-2021-22885: Possible Information Disclosure / Unintended Method
Execution in Action Pack

CVE-2021-22902: Possible Denial of Service vulnerability in Action
Dispatch

CVE-2021-22903: Possible Open Redirect Vulnerability in Action Pack

CVE-2021-22904: Possible DoS Vulnerability in Action Controller Token
Authentication");
  # https://weblog.rubyonrails.org/2021/5/5/Rails-versions-6-1-3-2-6-0-3-7-5-2-4-6-and-5-2-6-have-been-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdd3ebf6");
  # https://discuss.rubyonrails.org/t/cve-2021-22885-possible-information-disclosure-unintended-method-execution-in-action-pack/77868
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a3393a1");
  # https://discuss.rubyonrails.org/t/cve-2021-22902-possible-denial-of-service-vulnerability-in-action-dispatch/77866
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48f83df3");
  # https://discuss.rubyonrails.org/t/cve-2021-22903-possible-open-redirect-vulnerability-in-action-pack/77867
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?930053ff");
  # https://discuss.rubyonrails.org/t/cve-2021-22904-possible-dos-vulnerability-in-action-controller-token-authentication/77869
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2032461f");
  # https://vuxml.freebsd.org/freebsd/f7a00ad7-ae75-11eb-8113-08002728f74c.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0527300a");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22903");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22885");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-actionpack52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-actionpack60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-actionpack61");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"rubygem-actionpack52<5.2.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-actionpack60<6.0.3.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-actionpack61<6.1.3.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
