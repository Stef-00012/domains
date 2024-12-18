var registrar = NewRegistrar("none");
var dnsProvider = DnsProvider(NewDnsProvider("cloudflare"), 0);

function getDomainsList(filesPath) {
    var result = [];
    var files = glob.apply(null, [filesPath, true, ".json"]);

    for (var i = 0; i < files.length; i++) {
        var fileSplit = files[i].split('/')

        var name = fileSplit
            .pop()
            .replace(/\.json$/, "");

        var domain = fileSplit.pop()

        result.push({
            domain: domain,
            name: name,
            data: require(files[i])
        });
    }

    return result;
}

var domains = getDomainsList("./domains");

var commit = {}

for (var subdomain in domains) {
    var domain = domains[subdomain].domain
    var subdomainName = domains[subdomain].name;
    var domainData = domains[subdomain].data;
    var proxyState = domainData.proxied ? CF_PROXY_ON : CF_PROXY_OFF;

    if (!commit[domain]) commit[domain] = {
        records: []
    }
    
    // Handle mail
    if (commit[domain].mail) {
        var mailConfig = commit[domain].mail;
        
        commit[domain].records.push(
            A(subdomainName, IP("173.208.244.6")),
            MX(subdomainName, 20, "mail.stefdp.lol.")
        );
        
        if (mailConfig.DKIM) {
            var DKIMSubdomainName = `dkim._domainkey.${subdomainName}`;
            
            commit[DKIMSubdomainName] = {
                records: [
                    TXT(DKIMSubdomainName, mailConfig.DKIM)
                ]
            };
        }
        
        var autodiscoverSubdomainName = `autodiscover.${subdomainName}`;
        var autodiscoverTcpSubdomainName = `_autodiscover._tcp.${subdomainName}`;
        var autoconfigSubdomainName = `autoconfig.${subdomainName}`;
        var DMARCSubdomainName = `_dmarc.${subdomainName}`;
        
        commit[autodiscoverSubdomainName] = {
            records: [
                CNAME(autodiscoverSubdomainName, "mail.stefdp.lol.")
            ]
        };
        
        commit[autodiscoverTcpSubdomainName] = {
            records: [
                SRV(
                    autodiscoverTcpSubdomainName,
                    0,
                    65535,
                    443,
                    "mail.stefdp.lol."
                )
            ]
        };
        
        commit[autoconfigSubdomainName] = {
            records: [
                CNAME(autoconfigSubdomainName, "mail.stefdp.lol.")
            ]
        };
        
        commit[DMARCSubdomainName] = {
            records: [
                TXT(DMARCSubdomainName, mailConfig.DMARC || "v=DMARC1; p=reject")
            ]
        };
        
        domainData.records = domainData.records || {};
    }

    // Handle A records
    if (domainData.record.A) {
        for (var a in domainData.record.A) {
            commit[domain].records.push(
                A(subdomainName, IP(domainData.record.A[a]), proxyState)
            );
        }
    }

    // Handle AAAA records
    if (domainData.record.AAAA) {
        for (var aaaa in domainData.record.AAAA) {
            commit[domain].records.push(
                AAAA(subdomainName, domainData.record.AAAA[aaaa], proxyState)
            );
        }
    }

    // Handle CAA records
    if (domainData.record.CAA) {
        for (var caa in domainData.record.CAA) {
            var caaRecord = domainData.record.CAA[caa];
            commit[domain].records.push(
                CAA(
                    subdomainName,
                    caaRecord.flags,
                    caaRecord.tag,
                    caaRecord.value
                )
            );
        }
    }

    // Handle CNAME records
    if (domainData.record.CNAME) {
        // Allow CNAME record on root
        if (subdomainName === "@") {
            commit[domain].records.push(
                ALIAS(subdomainName, domainData.record.CNAME + ".", proxyState)
            );
        } else {
            commit[domain].records.push(
                CNAME(subdomainName, domainData.record.CNAME + ".", proxyState)
            );
        }
    }

    // Handle DS records
    if (domainData.record.DS) {
        for (var ds in domainData.record.DS) {
            var dsRecord = domainData.record.DS[ds];
            commit[domain].records.push(
                DS(
                    subdomainName,
                    dsRecord.keyTag,
                    dsRecord.algorithm,
                    dsRecord.digestType,
                    dsRecord.digest
                )
            );
        }
    }

    // Handle MX records
    if (domainData.record.MX) {
        for (var mx in domainData.record.MX) {
            var mxRecord = domainData.record.MX[mx]

            if (typeof mxRecord === "string") {
                commit[domain].records.push(
                    MX(
                        subdomainName,
                        10 + parseInt(mx),
                        domainData.record.MX[mx] + "."
                    )
                );
            } else {
                commit[domain].records.push(
                    MX(
                        subdomainName,
                        parseInt(mxRecord.priority) || 10 + parseInt(mx),
                        mxRecord.server + "."
                    )
                );
            }
        }
    }

    // Handle NS records
    if (domainData.record.NS) {
        for (var ns in domainData.record.NS) {
            commit[domain].records.push(NS(subdomainName, domainData.record.NS[ns] + "."));
        }
    }

    // Handle SRV records
    if (domainData.record.SRV) {
        for (var srv in domainData.record.SRV) {
            var srvRecord = domainData.record.SRV[srv];

            commit[domain].records.push(
                SRV(
                    subdomainName,
                    srvRecord.priority,
                    srvRecord.weight,
                    srvRecord.port,
                    srvRecord.target + "."
                )
            );
        }
    }

    if (domainData.record.TLSA) {
        for (var tlsa in domainData.record.TLSA) {
            var tlsaRecord = domainData.record.TLSA[tlsa];

            commit[domain].records.push(
                TLSA(
                    subdomainName,
                    tlsaRecord.usage,
                    tlsaRecord.selector,
                    tlsaRecord.matchingType,
                    tlsaRecord.certificate
                )
            )
        }
    }

    // Handle TXT records
    if (domainData.record.TXT) {
        if (Array.isArray(domainData.record.TXT)) {
            for (var txt in domainData.record.TXT) {
                commit[domain].records.push(TXT(subdomainName, domainData.record.TXT[txt].length <= 2046 ? "\"" + domainData.record.TXT[txt] + "\"" : domainData.record.TXT[txt]));
            }
        } else {
            commit[domain].records.push(TXT(subdomainName, domainData.record.TXT.length <= 2046 ? "\"" + domainData.record.TXT + "\"" : domainData.record.TXT));
        }
    }
}

var options = {
    no_ns: "true"
};

for (var commitDomain in commit) {
    commit[commitDomain].records.push(TXT("_zone-updated", "\"" + Date.now().toString() + "\""))

    D(commitDomain, registrar, dnsProvider, options, commit[commitDomain].records);
}