const https = require("https");
const fs = require("fs");

// Replace with your actual API endpoint
const API_URL = "https://api.nes.herodevs.com/api/catalog/packages";

// Function to make a GET request with query params
function fetchPage(pageNumber) {
  console.log(`Fetching Page ${pageNumber}...`);
  return new Promise((resolve, reject) => {
    // const parsedUrl = new URL(API_URL);
    // parsedUrl.searchParams.append("page", pageNumber);

    https
      .get(
        `https://api.nes.herodevs.com/api/catalog/packages?page=${pageNumber}`,
        (res) => {
          let data = "";

          res.on("data", (chunk) => {
            data += chunk;
          });

          res.on("end", () => {
            try {
              const json = JSON.parse(data);
              resolve(json);
            } catch (err) {
              reject(new Error(`Failed to parse JSON: ${err.message}`));
            }
          });
        }
      )
      .on("error", (err) => {
        reject(err);
      });
  });
}

// Sleep function to wait n milliseconds
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Helper to extract component and forkPoint
function processResults(results, allComponentsMap) {
  for (const item of results) {
    const versionForkPoints = item.versions.map((version) => {
      return version.oss.forkPoint;
    });

    if (item.component) {
      versionForkPoints.forEach((forkPoint) => {
        if (!allComponentsMap.has(item.componenty)) {
          allComponentsMap.set(item.component, {
            component: item.component,
            forkPoint,
          });
        } else {
          const existing = allComponentsMap.get(item.component);
          if (compareSemver(forkPoint, existing.forkPoint) > 0) {
            allComponentsMap.set(item.component, {
              component: item.component,
              forkPoint,
            });
          }
        }
      });
    }
  }
}

// Main function to fetch all pages
async function fetchAllPages() {
  const allComponentsMap = new Map();

  // Fetch the first page to get totalPages
  const firstPageData = await fetchPage(1);
  const totalPages = firstPageData.totalPages || 1;

  // Process first page
  processResults(firstPageData.results, allComponentsMap);

  // Fetch remaining pages sequentially with 2-second delay
  for (let page = 2; page <= totalPages; page++) {
    await sleep(2000); // wait 2 seconds
    const pageData = await fetchPage(page);
    processResults(pageData.results, allComponentsMap);
  }

  return Array.from(allComponentsMap.values());
}

// Run the script and save results to a local file
(async () => {
  try {
    const componentsWithForkPoints = await fetchAllPages();
    console.log(
      "Collected components and fork points:",
      componentsWithForkPoints.length
    );

    // Save to a JSON file
    fs.writeFileSync(
      "componentsWithForkPoints.json",
      JSON.stringify(componentsWithForkPoints, null, 2)
    );

    console.log("Saved results to componentsWithForkPoints.json");
  } catch (err) {
    console.error("Error fetching pages:", err.message);
  }
})();
