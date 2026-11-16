package attrib

import "testing"

func TestParseWHOISARIN(t *testing.T) {
	body := `
# ARIN WHOIS data
NetRange:       20.33.0.0 - 20.128.255.255
CIDR:           20.40.0.0/13, 20.48.0.0/12, 20.64.0.0/10, 20.80.0.0/12, 20.96.0.0/11
NetName:        MSFT
OriginAS:
Organization:   Microsoft Corporation (MSFT)
OrgName:        Microsoft Corporation
Country:        US
OrgAbuseEmail:  abuse@microsoft.com
Comment:        submit reports to abuse@microsoft.com
`
	rec := ParseWHOIS(body, "20.87.218.237")
	if rec.Org != "Microsoft Corporation" {
		t.Fatalf("org = %q", rec.Org)
	}
	if rec.Owner() != "Microsoft Corporation" {
		t.Fatalf("owner = %q", rec.Owner())
	}
	if rec.NetName != "MSFT" || rec.Country != "US" {
		t.Fatalf("netname/country = %s %s", rec.NetName, rec.Country)
	}
	if rec.CIDR != "20.80.0.0/12" {
		t.Fatalf("cidr = %q, want the most specific prefix containing the IP", rec.CIDR)
	}
	if rec.ASN != "" {
		t.Fatalf("empty OriginAS parsed as %q", rec.ASN)
	}
	if rec.Org == "abuse@microsoft.com" {
		t.Fatal("abuse contact was used as the org")
	}
}

func TestParseWHOISRIPE(t *testing.T) {
	body := `
% Abuse contact for '193.0.0.0 - 193.0.7.255' is 'abuse@ripe.net'
inetnum:        193.0.0.0 - 193.0.7.255
netname:        RIPE-NCC
descr:          RIPE Network Coordination Centre
country:        NL
organisation:   ORG-RIEN1-RIPE
org-name:       Reseaux IP Europeens Network Coordination Centre (RIPE NCC)
abuse-mailbox:  abuse@ripe.net
route:          193.0.0.0/21
origin:         AS3333
`
	rec := ParseWHOIS(body, "193.0.6.139")
	if rec.Org != "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)" {
		t.Fatalf("org = %q", rec.Org)
	}
	if rec.NetName != "RIPE-NCC" || rec.Country != "NL" || rec.ASN != "AS3333" {
		t.Fatalf("record = %+v", rec)
	}
	if rec.CIDR != "193.0.0.0/21" {
		t.Fatalf("cidr = %q", rec.CIDR)
	}
}

func TestParseWHOISInetnumFallback(t *testing.T) {
	body := "inetnum: 198.51.100.0 - 198.51.100.255\nnetname: EXAMPLE\n"
	rec := ParseWHOIS(body, "198.51.100.25")
	if rec.CIDR != "198.51.100.0/24" {
		t.Fatalf("cidr = %q", rec.CIDR)
	}
	if rec.Owner() != "EXAMPLE" {
		t.Fatalf("owner = %q", rec.Owner())
	}
}

func TestParseWHOISUnalignedRange(t *testing.T) {
	body := "NetRange: 203.0.113.10 - 203.0.113.20\nNetName: ODD\n"
	rec := ParseWHOIS(body, "203.0.113.15")
	if rec.CIDR != "203.0.113.10-203.0.113.20" {
		t.Fatalf("cidr = %q", rec.CIDR)
	}
}

func TestParseWHOISEmpty(t *testing.T) {
	for _, body := range []string{"", "% no match\n", "No match found\n"} {
		rec := ParseWHOIS(body, "8.8.8.8")
		if rec != (Record{}) {
			t.Fatalf("body %q parsed as %+v", body, rec)
		}
	}
}

func TestParseWHOISIgnoresIANAStub(t *testing.T) {
	body := "refer: whois.arin.net\norganisation: Administered by ARIN\ninetnum: 20.0.0.0 - 20.255.255.255\n"
	rec := ParseWHOIS(body, "20.87.218.237")
	if rec.Org != "" {
		t.Fatalf("org = %q", rec.Org)
	}
	if rec.CIDR != "20.0.0.0/8" {
		t.Fatalf("cidr = %q", rec.CIDR)
	}
}
