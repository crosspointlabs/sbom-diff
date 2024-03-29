window.addEventListener("load", () => {
    document.querySelector("button#diff").addEventListener("click", runDiff);
});

function runDiff() {
    const data = [];
    document.querySelectorAll("column textarea").forEach(textarea => {
        let section = textarea.parentNode.querySelector("section");
        section.innerHTML = "";
        data.push([textarea.parentNode.querySelector("section"), JSON.parse(textarea.value)]);
    })
    
    let mapped = data.map(([parent, sbom]) => {
        console.log(sbom);
        let components = enumerateComponents(sbom);
        let vulns = enumerateVulns(components, sbom);
        return [parent, components, vulns];
    })

    mapped.forEach(a => {
        let others = mapped.filter(x => x != a).map(k => Object.values(k[1])).reduce((a,b) => a.concat(b), []);
        Object.values(a[1]).filter(comp => 
            others.filter(comp2 => 
                (comp.purl && comp2.purl && comp.purl == comp2.purl) ||
                (comp.name == comp2.name && comp.version == comp2.version)
            ).length == 0
        ).forEach(k => k.modificationClass = "added")
        let othersVulns = mapped.filter(x => x != a).map(k => Object.values(k[2])).reduce((a,b) => a.concat(b), []);
        Object.values(a[2]).filter(vuln1 => 
            othersVulns.filter(vuln2 => 
                vuln1.id == vuln2.id
            ).length == 0
        ).forEach(k => k.modificationClass = "added")
    });

    mapped.forEach(([parent, comps, vulns]) => {
        appendComponentTree(parent, comps);
        appendVulnTree(parent, vulns);
    })
}
function enumerateComponents(sbom) {
    let components = {};
    (sbom.components|| []).forEach(component => {
        components[component["bom-ref"]] = component;
    });
    let mainComp = sbom.metadata?.component;
    if (mainComp) {
        console.log(mainComp);
        components[mainComp["bom-ref"]] = mainComp;
    }

    if (sbom.dependencies) {
        sbom.dependencies.forEach(({ref, dependsOn})=> {
            if (!dependsOn) return;
            components[ref].dependsOn = dependsOn.map(depRef => {
                let c = components[depRef];
                c.incomingRefs = (c.incomingRefs || 0) + 1;
                return c;
            });
        });
    }
    return components;
}


function enumerateVulns(components, sbom) {
    let vulns = {};
    (sbom.vulnerabilities || []).forEach(v => {
        v.affects.forEach((a) => {
            let {ref} = a;
            components[ref].affectedBy = components[ref].affectedBy || [];
            components[ref].affectedBy.push(v);
            a.components = a.components || [];
            a.components.push(components[ref]);
        })
        if (vulns[v.id]) {
            vulns[v.id].affects = vulns[v.id].affects.concat(v.affects);
        } else {
            vulns[v.id] = v;
        }
    })
    console.log(vulns);
    return vulns;
}


function c(parent, name, classes = []) {
    let k = document.createElement(name);
    k.className = classes.join(" ");
    parent.appendChild(k);
    return k;
}

function appendComponentTree(parentNode, components) {
    let det = c(parentNode, "details", ["header"]);
    let sum = c(det, "summary", ["header"]);
    sum.textContent = "Components";

    let roots = Object.values(components).filter(a => a.incomingRefs == undefined);
    roots.sort((a,b) => a.name < b.name ? -1 : 1);
    let changeCount = 0;
    roots.forEach(root => {
        changeCount += writeComponentTree(det, root);
    })
    if (changeCount > 0) {
        let count = c(sum, "span");
        count.textContent = changeCount;
    }
}

function writeComponentTree(parentNode, dep) {
    let container = c(parentNode, "details", [dep.modificationClass, "tree"]);
    let summary = c(container, "summary", ["tree"]);
    summary.textContent = `${dep.name} @ ${dep.version} (${dep.incomingRefs || 0})`;
    summary.setAttribute("data-bom-ref", dep["bom-ref"]);
    if (dep.dependsOn && dep.dependsOn.length > 0) {
        let changes = dep.dependsOn.map(c => writeComponentTree(container, c)).reduce((a,b) => a+b, 0);
        return changes + (dep.modificationClass == "added" ? 1 : 0)
    } else {
        container.className += " leaf";
        summary.className += " leaf";
        return (dep.modificationClass == "added" ? 1 : 0);
    }
}

function possiblyParseNumber(x) {
    if (/^[0-9]+$/.test(x)) return parseInt(x, 10);
    return x;
}

function appendVulnTree(parentNode, vulns) {
    let det = c(parentNode, "details", ["header"]);
    let sum = c(det, "summary", ["header"]);
    sum.textContent = "Vulnerabilities";

    if (Object.keys(vulns).length == 0) {
        c(det, "i").textContent = "No vulnerabilities in report";
        return;
    }

    let ids = Object.keys(vulns);
    ids.sort((a, b) => {
        let ka = a.split("-");
        let kb = b.split("-");
        let min = Math.min(ka.length, kb.length);
        for (let i = 0; i < min; i++) {
            let [ap, bp] = [ka[i], kb[i]].map(x => possiblyParseNumber(x));
            if (ap < bp) return -1;
            if (ap > bp) return 1;
        }
        return ka.length - kb.length;
    });
    let changeCount = 0;
    ids.forEach(id => {
        let vuln = vulns[id];
        if (vuln.modificationClass == "added") changeCount++;
        let container = c(det, "details", [vuln.modificationClass, "tree"]);
        let summary = c(container, "summary", ["tree"]);
        summary.textContent = id;
        (vuln.affects || []).map(a => {
            let d = c(container, "details", [vuln.modificationClass, "tree", "leaf"]);
            for(let comp of a.components) { 
                let s = c(d, "summary", ["tree", "leaf"]);
                s.textContent = `${comp.name} @ ${comp.version}`;
            }
        });
    })
    if (changeCount > 0) {
        let count = c(sum, "span");
        count.textContent = changeCount;
    }
}