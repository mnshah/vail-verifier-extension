chrome.runtime.onInstalled.addListener(async () => {
    console.log("Installed Artifact Worker...");
  });

chrome.runtime.onMessage.addListener(async (event) => {
    if (event.type === "fetch-artifact") {
        const artifact = await fetchArtifact(event);
        return artifact;
    }
});

async function fetchArtifact(event) {
    console.log("Fetching artifact...");
    const artifact = await fetch(event.request.url);
    return artifact;
}