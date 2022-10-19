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
        let components = createTree(sbom);
        return [parent, components];
    })
    mapped.forEach(a => {
        let others = mapped.filter(x => x != a).map(k => Object.values(k[1])).reduce((a,b) => a.concat(b), []);
        Object.values(a[1]).filter(comp => 
            others.filter(comp2 => 
                (comp.purl && comp2.purl && comp.purl == comp2.purl) ||
                comp.name == comp2.name && comp.version == comp2.version
            ).length == 0
        ).forEach(k => k.modificationClass = "added")
    });


    mapped.forEach(([parent, comps]) => {
        appendTree(parent, comps);
    })
}
function createTree(sbom) {
    let components = {};
    sbom.components.forEach(component => {
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

function c(parent, name) {
    let k = document.createElement(name);
    parent.appendChild(k);
    return k;
}

function appendTree(parentNode, components) {
    let roots = Object.values(components).filter(a => a.incomingRefs == undefined);
    roots.sort((a,b) => a.name < b.name ? -1 : 1);
    roots.forEach(root => {
        writeTree(parentNode, root);
    })
}

function writeTree(parentNode, dep) {
    let container = c(parentNode, "details");
    container.className = dep.modificationClass;
    let summary = c(container, "summary");
    summary.textContent = `${dep.name} @ ${dep.version}`;
    if (dep.dependsOn && dep.dependsOn.length > 0) {
        dep.dependsOn.map(c => writeTree(container, c));
    } else {
        container.className += " leaf";
        summary.className += " leaf";
    }
}